import configparser
import io
import logging
import os.path
import sys
import tempfile
import unittest.mock

import systemlogger


def test_basic_loggers():
    parser = configparser.RawConfigParser()
    with tempfile.TemporaryDirectory() as dirname:
        parser.add_section("logging")
        parser.set("logging", "logfile_directory", dirname)
        parser.set("logging", "level", "info")
        logger = systemlogger.getLogger(config_filename=parser, name="test_basic")
        assert logger.level == logging.INFO  # nosec B101
        logger.debug("test")
        assert len(logger.handlers) == 1  # nosec B101
        assert os.path.isfile(os.path.join(dirname, "test_basic.log"))  # nosec B101


def test_console_logger():
    parser = configparser.RawConfigParser()
    parser.add_section("logging")
    parser.set("logging", "console", "true")
    parser.set("logging", "level", "info")
    stdout = io.StringIO()
    stderr = io.StringIO()
    with unittest.mock.patch("sys.stdout", new=stdout):
        with unittest.mock.patch("sys.stderr", new=stderr):
            logger = systemlogger.getLogger(config_filename=parser, name="test_console")
            logger.debug("test test")
            logger.info("test info")
            logger.warning("test warning")
            logger.error("test error")
    assert logger.level == logging.INFO  # nosec B101
    assert len(logger.handlers) == 2  # nosec B101
    assert stdout.getvalue() == "test info\ntest warning\n"  # nosec B101
    assert stderr.getvalue() == "test error\n"  # nosec B101


def test_loki_logger():
    parser = configparser.RawConfigParser()
    parser.add_section("logging")
    parser.set(
        "logging",
        "loki_url",
        "http://username:password@localhost:9100/loki/api/v1/push",
    )
    parser.set("logging", "level", "warning")
    stdout = io.StringIO()
    with unittest.mock.patch("sys.stdout", new=stdout):
        logger = systemlogger.getLogger(config_filename=parser, name="test_loki")
        logger.debug("test test")
        logger.info("test info")
        logger.warning("test warning")
        logger.error("test error")
    assert logger.level == logging.WARNING  # nosec B101
    assert len(logger.handlers) == 1  # nosec B101
    assert (
        stdout.getvalue()
        == "[Loki unavailable] test warning\n[Loki unavailable] test error\n"
    )  # nosec B101
