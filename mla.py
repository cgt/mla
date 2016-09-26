#!/usr/bin/env python3

import fileinput
import operator
import re


re_line = re.compile('postfix/(.+)\[\d+\]:')
re_dnsblog = re.compile(
    'postfix/dnsblog\[\d+\]: addr ([0-9a-f.:]+) listed by domain (.+) as .+$')
re_ps_connect = re.compile(
    'postfix/postscreen\[\d+\]: CONNECT from \[(.+)\]:\d+ to')


def process_line(line):
    match = re_line.search(line)
    if not match:
        return

    typ = match.group(1)
    if typ == "postscreen":
        process_ps(line)
    elif typ == "dnsblog":
        process_dnsblog(line)


def process_ps(line):
    global log_data
    match = re_ps_connect.search(line)
    if not match:
        return

    ip = match.group(1)
    if ip not in log_data.keys():
        log_data[ip] = set()


def process_dnsblog(line):
    global log_data
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


log_data = {}


def main():
    for line in fileinput.input():
        process_line(line)


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

if __name__ == "__main__":
    main()

    from pprint import pprint
    # pprint(dnsbl_hit_count(log_data))
    pprint(not_caught_by_spamhaus(log_data))
