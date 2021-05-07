#!/usr/bin/env python3

import argparse
import dateutil.parser
import gzip
import logging
import os
import os.path
import sys
import re
from datetime import date, timedelta

try:
    import ujson as json
except ImportError:
    import json


log = logging.getLogger(__name__)

FILTER_BOTS = "user_agent~(http|bot|crawl|spider|search)"
NGINX_LOG_DIR = "/var/log/nginx"
DEFAULT_FORMAT = "%(host)-15.15s %(status)s %(request_time)6s %(country)-2s %(remote_addr)-15s %(method)-4s %(uri)s"
NCSA_FORMAT = '%(remote_addr)s - %(remote_user)s [%(time)s] "%(request)s" %(status)s %(body_bytes_sent)s'
FIELD_SHORTCUTS = {
    "ip": "remote_addr",
    "ua": "user_agent",
    "date": "time",
    "time": "request_time",
    "req": "uri",
    "ref": "referer",
    "cc": "country",
}


def get_default_nginx_log_path():
    return os.path.join(NGINX_LOG_DIR, "access.log")


def sorted_log_files(filenames, reverse=False):
    """Sort a sequence of log filenames that are rotated."""

    def sort_key(filename):
        filename = os.path.basename(filename)
        parts = filename.split(".")
        if len(parts) < 3 or not parts[2].isdigit():
            return 0
        return int(parts[2])

    return sorted(filenames, key=sort_key, reverse=reverse)


def get_nginx_logs_for_date(target_date):
    """
    Check the access logs and return a list of access log files which contain the relevant log files
    for the given :target_date:
    :param date target_date: The target date
    :return list[str]: list of files which can contain logs for the given :target_date:
    """
    nginx_access_logs = sorted_log_files(
        f
        for f in os.listdir(NGINX_LOG_DIR)
        if re.match(r"^access\.log(\.\d+\.gz)?$", f)
    )
    result_log_files = []
    last_mtime = None
    last_log = None

    for log_file in nginx_access_logs:
        curr_mtime = date.fromtimestamp(
            os.stat(os.path.join(NGINX_LOG_DIR, log_file)).st_mtime
        )

        if curr_mtime == target_date:
            result_log_files.append(os.path.join(NGINX_LOG_DIR, log_file))
            if last_log is not None:
                result_log_files.append(os.path.join(NGINX_LOG_DIR, last_log))

        if last_log and curr_mtime > target_date and curr_mtime > last_mtime:
            result_log_files.append(os.path.join(NGINX_LOG_DIR, log_file))

        if last_mtime and curr_mtime > target_date > last_mtime:
            # current log we're looking at is the last log for :target_date:
            result_log_files.append(os.path.join(NGINX_LOG_DIR, log_file))
            result_log_files.append(os.path.join(NGINX_LOG_DIR, last_log))

        if last_mtime and curr_mtime < target_date < last_mtime:
            result_log_files.append(os.path.join(NGINX_LOG_DIR, last_log))
            break

        last_log = log_file
        last_mtime = curr_mtime

    # no matching log files found. oldest log may contain the needed log, so we return that
    if len(result_log_files) == 0:
        result_log_files.append(os.path.join(NGINX_LOG_DIR, nginx_access_logs[-1:][0]))

    return sorted_log_files(set(result_log_files), reverse=True)


def compile_filter(logfilter):
    """
    Given a filter string, generate a function that will return True if the
    filter matches the given argument.

    Filter strings look like <field-name>=<value> or <field-name>~<regex>

    :param str logfilter: Filter specification
    :return: dict[str, V] -> bool
    """

    # Find first occurrence of [=~]
    # http://stackoverflow.com/questions/19191287/python-find-first-non-matching-character
    match = re.search(r"\!?[~=]", logfilter)
    if not match:
        raise RuntimeError("Invalid filter! No operator =/~/!=/!~ given.")

    token = match.group()
    field, value = logfilter.split(token, 1)

    # expand shortcuts
    field = FIELD_SHORTCUTS.get(field, field)

    if token == "=":
        return lambda line: line.get(field) == value
    elif token == "!=":
        return lambda line: line.get(field) != value
    elif token == "~":
        regex = re.compile(value)
        return lambda line: regex.search(line.get(field))
    elif token == "!~":
        regex = re.compile(value)
        return lambda line: not regex.search(line.get(field))


def compile_filters(filters):
    """Compile a sequence of filters to one function that returns True if all
    filters match the given argument."""
    filter_funcs = []
    for logfilter in filters:
        filter_funcs.append(compile_filter(logfilter))
    return lambda line: all(filter_func(line) for filter_func in filter_funcs)


def get_date_filter(target_date):
    """Get a filter string that filters only lines for the given date."""
    return "time~{}-{:02d}-{:02d}".format(
        target_date.year, target_date.month, target_date.day
    )


def smart_open(filename):
    """Wrapper for open() that also works with gzipped files."""
    if filename.endswith(".gz"):
        return gzip.open(filename, "rt")
    return open(filename, "r")


def read_lines_from_paths(paths):
    """Given a sequence of file paths, yield lines of decoded JSON data."""
    if isinstance(paths, str):
        paths = [paths]
    for file in paths:
        if isinstance(file, str):
            file = smart_open(file)
        try:
            for line in file:
                # nginx does some weird escaping of log data. doing line.replace
                # on every line is expensive, so only do it when decoding fails.
                try:
                    yield json.loads(line)
                except ValueError:
                    try:
                        yield json.loads(line.replace("\\x", "\\u00"))
                    except ValueError:
                        log.warning("Malformed JSON line, skipping: %r", line)
        finally:
            file.close()


def get_available_fields(paths):
    """Given a sequence of file paths, find the available fields."""
    fields = set()
    for line in read_lines_from_paths(paths):
        for key in line:
            fields.add(key)
    return fields


def read_logs(paths, filters, out_format, fields):
    """Read logs and yield lines that can be output based on the given filters
    and output format or fields to print."""
    filter_func = compile_filters(filters) if filters else None
    for line in read_lines_from_paths(paths):
        if filter_func and not filter_func(line):
            continue
        if "request" in line:
            # we call repr to escape control characters like \x05, to prevent these
            # from messing up the user's terminal. we strip away the first and last
            # characters, which will be single or double quotes, in order to
            # preserve old behaviour. the performance impact from this is neglible.
            line["request"] = repr(line["request"])[1:-1]
        if not out_format and not fields:
            fields = sorted(line.keys())
        if fields:
            yield "\t".join(
                str(line.get(FIELD_SHORTCUTS.get(field, field), "-"))
                for field in fields
            )
        else:
            try:
                yield out_format % line
            except KeyError as e:
                log.warning(e)
                continue
            except ValueError as e:
                print(f"Line is type {type(line)} and contains:\n{line}")
                print(f"out format: {out_format}")
                raise


def parse_arguments(cmdline=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fields", help="Comma separated list of fields to display")
    parser.add_argument(
        "--bots", action="store_true", help="Short for --filter %s" % FILTER_BOTS
    )
    parser.add_argument("--format", help="Format string to display fields")
    parser.add_argument(
        "--list-fields", action="store_true", help="Display a list of available fields"
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help="Filter to apply. Format: <field>=<str> or <field>~<regex> or <field>!~<regex>",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Display debug output"
    )
    parser.add_argument(
        "--ncsa", "--apache", action="store_true", help="Output in NCSA format."
    )

    fileoptions = parser.add_mutually_exclusive_group()
    fileoptions.add_argument("--filename", help="Path of nginx logfile to parse")
    fileoptions.add_argument(
        "--today",
        action="store_true",
        help="Analyze logs and outputs today's log lines",
    )
    fileoptions.add_argument(
        "--yesterday",
        action="store_true",
        help="Analyze logs and outputs yesterday's log lines",
    )
    fileoptions.add_argument(
        "--days-ago",
        type=int,
        help="Analyze logs and outputs for a specific number of days ago",
    )
    fileoptions.add_argument(
        "--date", help="Analyze logs and outputs for a specific date"
    )

    return parser.parse_args(cmdline)


def main():
    args = parse_arguments()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)

    paths = None
    filters = []

    if args.filename is not None:
        paths = [args.filename]
    elif args.today or args.yesterday or args.days_ago or args.date:
        if args.today:
            target_date = date.today()
        elif args.yesterday:
            target_date = date.today() - timedelta(days=1)
        elif args.days_ago:
            target_date = date.today() - timedelta(days=args.days_ago)
        elif args.date:
            try:
                dt = dateutil.parser.parse(args.date)
            except ValueError:
                print("could not parse date from {!r}".format(args.date))
                sys.exit(1)
            target_date = dt.date()
        paths = get_nginx_logs_for_date(target_date)
        filters.append(get_date_filter(target_date))

    for filter_arg in args.filter:
        filters.append(filter_arg)

    if args.list_fields:
        fields = get_available_fields(paths or [get_default_nginx_log_path()])
        print("Available fields:", ", ".join(fields))
        return

    fields = args.fields.split(",") if args.fields else None

    if args.format:
        out_format = args.format
    elif args.ncsa:
        out_format = NCSA_FORMAT
    elif fields:
        out_format = None
    else:
        out_format = DEFAULT_FORMAT

    if not paths:
        paths = [sys.stdin]

    try:
        for out in read_logs(paths, filters, out_format, fields):
            try:
                print(out)
            # this can happen if you pipe output into `head` or `tail`
            except:
                raise
            # except BrokenPipeError:
            #     return
            # except UnicodeEncodeError as e:
            #     raise RuntimeError(out)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
