#!/usr/bin/env python3
import re
import os
import sys
import logging

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-F", "--split", help="splitor, must escape code",
                    action="store", default=' ', type=str, dest="splitor")
parser.add_argument("-p", "--format", help="print data format",
                    action="store", default='', type=str, dest="format")
parser.add_argument("-e", "--escape", help="include escape code",
                    action="store_true", dest="escape")
parser.add_argument("-v", "--verbose", help="",
                    action="store_true", dest="verbose")

parser.add_argument("-t", "--test", help="",
                    action="store_true", dest="test")
parser.add_argument("value", nargs=argparse.REMAINDER, type=int)
args = parser.parse_args()


# print(args, file=sys.stderr)


def do_print(formats, items, line):
    if args.verbose:
        print(items)
        print(line)
    s = formats.replace('$0', line)
    n = len(items)

    pattern = list(items)
    pattern.insert(0, line)

    for i in range(n):
        s = s.replace('${}'.format(i + 1), items[i])
        s = s.replace('${}'.format(-(i + 1)), items[n - 1 - i])
    print(s)
    return s

    for i in range(n):
        # replace id
        s = s.replace('{{{}'.format((i + 1)), '{{{}'.format(i))
        s = s.replace('{{{}'.format(-(i + 1)), '{{{}'.format(n - 1 - i))

    # replace format id
    print(s)
    s = s.format(*pattern)

    return s


def process(line):
    splitor = args.splitor
    line = line.strip()

    items = line.split(splitor)

    if args.format:
        s = do_print(args.format, items, line)
        if args.escape:
            s = s.decode('unicode-escape')
        print(s)


def main():
    splitor = args.splitor
    args.splitor = splitor.encode('utf8').decode('unicode-escape')

    if args.test:
        args.splitor = ' '
        args.format = '{2} {-1}'
        line = '123456 hehehh 123'
        process(line)
        return

    fd = sys.stdin
    for line in fd:
        if not line:
            break

        process(line)


if __name__ == '__main__':
    main()
