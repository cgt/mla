#!/usr/bin/env python3

# mla - mail.log analyzer
# Written in 2016 by Christoffer G. Thomsen <chris@cgt.name>
#
# To the extent possible under law, the author(s) have dedicated
# all copyright and related and neighboring rights to this software
# to the public domain worldwide. This software is distributed
# without any warranty. You should have received a copy of the CC0
# Public Domain Dedication along with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.

import argparse
import json
import operator
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
    return {ip: lists for ip, lists in log_data.items() if "zen.spamhaus.org" not in lists and len(lists) >= 1}


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


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return sorted(list(obj))
        return json.JSONEncoder.default(self, obj)


def main(args):
    log_data = {}
    for line in args.file:
        process_line(line, log_data)

    try:
        analyzer = analyzers[args.analyzer]
        x = analyzer(log_data)
        print(json.dumps(x, sort_keys=True, indent=4, cls=SetEncoder))
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
