#!/usr/bin/env python3

import argparse
import operator
from pprint import pprint
import re
import sys


re_line = re.compile('postfix/(.+)\[\d+\]:')
re_dnsblog = re.compile(
    'postfix/dnsblog\[\d+\]: addr ([0-9a-f.:]+) listed by domain (.+) as .+$')
re_ps_connect = re.compile(
    'postfix/postscreen\[\d+\]: CONNECT from \[(.+)\]:\d+ to')


def process_line(line, log_data):
    match = re_line.search(line)
    if not match:
        return

    typ = match.group(1)
    if typ == "postscreen":
        process_ps(line, log_data)
    elif typ == "dnsblog":
        process_dnsblog(line, log_data)


def process_ps(line, log_data):
    match = re_ps_connect.search(line)
    if not match:
        return

    ip = match.group(1)
    if ip not in log_data.keys():
        log_data[ip] = set()


def process_dnsblog(line, log_data):
    match = re_dnsblog.search(line)
    if not match:
        print("Weird dnsblog line: {}".format(line))
        return

    ip = match.group(1)
    dnsbl = match.group(2)

    try:
        log_data[ip].add(dnsbl)
    except KeyError:
        log_data[ip] = set([dnsbl])


def not_caught_by_spamhaus(log_data):
    """
    Returns a dict like log_data but with IPs that were found in
    zen.spamhaus.org removed.
    """
    return {ip: lists for ip, lists in log_data.items() if "zen.spamhaus.org" not in lists}


def dnsbl_hit_count(log_data):
    """Counts how many hosts were found in each dnsbl."""
    import collections
    import operator

    y = collections.defaultdict(int)
    for v in log_data.values():
        for bl in v:
            y[bl] += 1
    return sorted(y.items(), key=operator.itemgetter(1), reverse=True)


# Maps from CLI arg to analyzer function.
analyzers = {
    "hits": dnsbl_hit_count,
    "notspamhaus": not_caught_by_spamhaus,
}


def main(args):
    log_data = {}
    for line in args.file:
        process_line(line, log_data)

    try:
        analyzer = analyzers[args.analyzer]
        pprint(analyzer(log_data))
    except KeyError:
        print('Invalid analyzer "{}". Valid: {}'.format(
            args.analyzer, sorted(analyzers.keys())))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("analyzer", choices=sorted(analyzers.keys()))
    parser.add_argument("file", nargs="?",
                        type=argparse.FileType("r"), default=sys.stdin)
    args = parser.parse_args()

    main(args)
