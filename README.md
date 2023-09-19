SystemLogger
============


..image:: https://pyup.io/repos/github/d9pouces/SystemLogger/shield.svg
:target: https://pyup.io/repos/github/d9pouces/SystemLogger/
:alt: Updates

Create and configure a logger using a global configuration file.
This module is intended for logging my Python system scripts, without redeclaring a lot of boilerplate.
This module is not meant to be highly customizable, but to have the same logging configuration in scripts with a
minimal effort.

The default configuration file is `/etc/python_logging.ini`.

Usage
-----

```bash
python3 -m pip install systemlogger
cat << EOF | sudo tee /etc/python_logging.ini
[logging]
sentry_dsn = https://username@sentry.example.com/1
loki_url = https://username:password@localhost:3100/loki/api/v1/push
syslog_url = tcp://127.0.0.1:10514
# only udp:// and tcp:// protocols can be used for syslog
logfile_directory = /tmp
# the filename will be /tmp/{application}.log
logfile_max_size = 1000000
# if max_size is not set (or is 0), the file will never be rotated
logfile_backup_count = 3
# number of backup files (for example, only /tmp/{application}.log.1 is created if logfile_backup_count == 1)
console = true
# errors and above are sent to stderr, infos and below are sent to stdout
level = info
# minimal level of transmitted log records
source = python
# added as "log_source" tag in sentry and loki
EOF
python3 -c 'from systemlogger import getLogger ; logger = getLogger(name="demo") ; logger.warning("log warning test") ; logger.error("log error test")'
```

In Grafana/Loki and in Sentry, you can now select all Python scripts with the `log_source` tag and a specific script
with
the `application` tag.
