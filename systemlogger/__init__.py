# ##############################################################################
#  Copyright (c) Matthieu Gallet <github@19pouces.net> 2023.                   #
#  Please check the LICENSE file for sharing or distribution permissions.      #
# ##############################################################################
"""All the main functions."""
import configparser
import logging
import os
import socket
import sys
import urllib.parse
from logging.handlers import (
    SYSLOG_UDP_PORT,
    QueueHandler,
    QueueListener,
    RotatingFileHandler,
    SysLogHandler,
)
from multiprocessing import Queue
from typing import Union, Dict

try:
    import sentry_sdk
except ImportError:
    sentry_sdk = None
try:
    # noinspection PyPackageRequirements
    import logging_loki
    # noinspection PyPackageRequirements
    import logging_loki.emitter as loki_emitter
except ImportError:
    logging_loki = None
    loki_emitter = None


class ConsoleStdoutFilter(logging.Filter):
    """Errors and above are not sent to stderr."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Errors and above are not sent to stderr."""
        return record.levelno < logging.ERROR


class ConsoleStderrFilter(logging.Filter):
    """Only errors and above sent to stderr."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Only errors and above sent to stderr."""
        return record.levelno >= logging.ERROR


class LoggerConfigurator:
    """Create and configure the logger, step-by-step."""

    levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "fatal": logging.CRITICAL,
        "crit": logging.CRITICAL,
        "critical": logging.CRITICAL,
    }

    def __init__(
        self,
        config: Union[str, configparser.RawConfigParser] = "/etc/python_logging.ini",
        config_section: str = "logging",
        extra_tags: Dict[str, str] = None,
    ):
        """Initialize the configurator."""
        self.config_parser = self.get_config_parser(config)
        self.extra_tags = extra_tags or {}
        try:
            self.hostname = socket.gethostname()
        except socket.gaierror:
            self.hostname = "localhost"
        self.config_section = config_section

    def get_logger(
        self, name: str = "default", application: str = "python"
    ) -> logging.Logger:
        """Create the logger and configure it."""
        logger = logging.getLogger(name=name)
        self.configure_logger(logger)
        result = ""
        if self.configure_loki(logger, application):
            result += " loki"
        if self.configure_syslog(logger):
            result += " syslog"
        if self.configure_sentry(logger, application):
            result += " sentry"
        if self.configure_file(logger, application):
            result += " logfile"
        if self.configure_console(logger):
            result += " console"
        if not result:
            result += " [no configuration]"
        logger.debug("Configured logging:%s", result)
        return logger

    def configure_logger(self, logger: logging.Logger) -> bool:
        """Set the default configuration for the new logger."""
        level = self.config_parser.get(self.config_section, "level", fallback="warn")
        level = self.levels.get(level.lower(), logging.WARNING)
        logger.setLevel(level)
        logger.propagate = False
        requests_ca_bundle = self.config_parser.get(
            self.config_section, "requests_ca_bundle", fallback=None
        )
        if requests_ca_bundle:
            os.environ["REQUESTS_CA_BUNDLE"] = requests_ca_bundle
        return True

    def configure_syslog(self, logger: logging.Logger) -> bool:
        """Configure syslog if required."""
        syslog_url = self.config_parser.get(
            self.config_section, "syslog_url", fallback=None
        )
        if not syslog_url:
            return False
        parsed_url = urllib.parse.urlparse(syslog_url)
        if "tcp" in parsed_url.scheme:
            socktype = socket.SOCK_STREAM
        else:
            socktype = socket.SOCK_DGRAM
        port = parsed_url.port or SYSLOG_UDP_PORT
        hostname = parsed_url.hostname or "localhost"
        logger.addHandler(SysLogHandler(address=(hostname, port), socktype=socktype))
        return True

    def configure_loki(
        self, logger: logging.Logger, application: str = "python"
    ) -> bool:
        """Configure Loki if available and if the URL is set."""
        if logging_loki is None:
            return False

        class LokiQueueHandler(QueueHandler):
            def __init__(self, queue: Queue, **kwargs):
                """Create new logger handler with the specified queue and kwargs for the `LokiHandler`."""
                super().__init__(queue)
                self.handler = LokiHandler(**kwargs)  # noqa: WPS110
                self.listener = QueueListener(self.queue, self.handler)
                self.listener.start()

        class LokiHandler(logging_loki.LokiHandler):
            # noinspection PyMethodOverriding
            @staticmethod
            def handleError(record: logging.LogRecord):
                if hasattr(record, "message"):
                    msg = record.message
                elif hasattr(record, "msg"):
                    msg = record.msg
                else:
                    msg = str(record)
                print(f"[Loki unavailable] {msg}")

        loki_url = self.config_parser.get(
            self.config_section, "loki_url", fallback=None
        )
        threaded = self.config_parser.getboolean(
            self.config_section, "loki_threaded", fallback=False
        )
        log_source = self.config_parser.get(
            self.config_section, "log_source", fallback="python"
        )
        hostname = self.config_parser.get(
            self.config_section, "hostname", fallback=self.hostname
        )
        if not loki_url:
            return False
        loki_emitter.LokiEmitter.level_tag = "level"
        parsed_url = urllib.parse.urlparse(loki_url)
        scheme = parsed_url.scheme
        if scheme.startswith("loki"):
            scheme = f"http{scheme[4:]}"
        url = f"{scheme}://{parsed_url.hostname}"
        if parsed_url.port:
            url += f":{parsed_url.port}"
        url += parsed_url.path
        if parsed_url.query:
            url += f"?{parsed_url.query}"
        tags = {
            "application": application,
            "log_source": log_source,
            "hostname": hostname,
        }
        tags.update(self.extra_tags)
        kwargs = {
            "url": url,
            "tags": tags,
            "auth": (parsed_url.username or "", parsed_url.password or ""),
            "version": "1",
        }
        if threaded:
            handler = LokiQueueHandler(Queue(-1), **kwargs)
        else:
            handler = LokiHandler(**kwargs)
        logger.addHandler(handler)
        return True

    @staticmethod
    def get_config_parser(
        filename: Union[str, configparser.RawConfigParser]
    ) -> configparser.RawConfigParser:
        """Return a config parser."""
        if isinstance(filename, configparser.RawConfigParser):
            return filename
        parser = configparser.RawConfigParser()
        parser.read([filename])
        return parser

    def configure_console(self, logger: logging.Logger) -> bool:
        """Display log entries to the console."""
        use_console = self.config_parser.getboolean(
            self.config_section, "console", fallback=False
        )
        if not use_console:
            return False
        handler_out = logging.StreamHandler(sys.stdout)
        handler_out.addFilter(ConsoleStdoutFilter())
        logger.addHandler(handler_out)
        handler_err = logging.StreamHandler(sys.stderr)
        handler_err.addFilter(ConsoleStderrFilter())
        logger.addHandler(handler_err)
        return True

    def configure_file(
        self, logger: logging.Logger, application: str = "python"
    ) -> bool:
        """Write a log file."""
        log_directory = self.config_parser.get(
            self.config_section, "logfile_directory", fallback=None
        )
        max_size = self.config_parser.getint(
            self.config_section, "logfile_max_size", fallback=0
        )
        backup_count = self.config_parser.getint(
            self.config_section, "logfile_backup_count", fallback=0
        )
        if not log_directory:
            return False
        try:
            os.makedirs(log_directory, exist_ok=True)
        except OSError:
            logger.exception("Unable to create directory '%s'.", log_directory)
            return False
        filename = os.path.join(log_directory, f"{application}.log")
        try:
            if max_size > 0:
                handler = RotatingFileHandler(
                    filename, maxBytes=max_size, backupCount=backup_count
                )
            else:
                handler = logging.FileHandler(filename)
        except OSError:
            logger.exception("Unable to create file '%s'.", filename)
            return False
        logger.addHandler(handler)
        return True

    def configure_sentry(
        self, logger: logging.Logger, application: str = "python"
    ) -> bool:
        """Configure Sentry, if available and if required."""
        if sentry_sdk is None:
            return False
        log_source = self.config_parser.get(
            self.config_section, "log_source", fallback="python"
        )
        sentry_dsn = self.config_parser.get(
            self.config_section, "sentry_dsn", fallback=None
        )
        if not sentry_dsn:
            return False
        sentry_sdk.init(sentry_dsn)
        sentry_sdk.set_tag("log_source", log_source)
        sentry_sdk.set_tag("application", application)
        for k, v in self.extra_tags.items():
            sentry_sdk.set_tag(k, v)
        return True


def getLogger(
    name="python",
    config_filename: str = "/etc/python_logging.ini",
    config_section="logging",
    extra_tags: Dict[str, str] = None,
) -> logging.Logger:
    """Create and configure a new logger.

    :param name: name of the new logger, added in Loki and Sentry as the "application" tag.
    :param config_filename: name of the configuration file. Can also be a RawConfigParser.
    :param config_section: section to look at in the configuration file.
    :param extra_tags: additional tags to add to the Loki and Sentry logs.
    :return: the new logger.
    """
    configurator = LoggerConfigurator(
        config=config_filename, config_section=config_section, extra_tags=extra_tags
    )
    return configurator.get_logger(name=name, application=name)
