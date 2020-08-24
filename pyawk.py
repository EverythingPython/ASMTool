#!/usr/bin/env python3
import re
import os
import sys
import logging

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-F", "-s", "--split", help="splitor, must escape code",
                    action="store", default=' ', type=str, dest="splitor")
parser.add_argument("-p", "--print", "--format", help="print data in format, default use {{}}, -h to know others",
                    action="store", default='', type=str, dest="format")

parser.add_argument("-b", "--bracket", help="(default) change id flag to {}, e.g. {1}",
                    action="store_true", dest="bracket")
parser.add_argument("-d", "--dolar", help="change id flag to $, e.g. $1",
                    action="store_true", dest="dolar")
parser.add_argument("-c", "--percent", help="change id flag to %%, e.g. %%1",
                    action="store_true", dest="percent")
parser.add_argument("-e", "--escape", help="include escape code",
                    action="store_true", dest="escape")
parser.add_argument("-v", "--verbose", help="",
                    action="store_true", dest="verbose")
parser.add_argument("-t", "--test", help="",
                    action="store_true", dest="test")
parser.add_argument("value", nargs='*')
args = parser.parse_args()
print(args, file=sys.stderr)


def do_print(formats, items, line):
    if args.verbose:
        print("formats:{}".format(formats))
        print('items:{}'.format(items))
        print('line:{}'.format(line))

    n = len(items)
    s = formats

    pattern = list(items)
    # 0 as whole string in the line
    pattern.insert(0, line)

    for i in range(n):
        # replace id
        # 0 is special for whole string
        # positive from 1 to n (total n patterns)
        # negative to positive, -(i+1) means n - i, e.g. -1 means n

        if args.dolar:
            s = s.replace('${}'.format(i), '{{{}}}'.format(i))
            s = s.replace('${}'.format(-(i + 1)), '{{{}}}'.format(n - i))
        elif args.percent:
            s = s.replace('%{}'.format(i), '{{{}}}'.format(i))
            s = s.replace('%{}'.format(-(i + 1)), '{{{}}}'.format(n - i))
        else:
            # s = s.replace('{{{}'.format((i + 1)), '{{{}'.format(i))
            s = s.replace('{{{}'.format(-(i + 1)), '{{{}'.format(n - i))

    # do format
    res = s.format(*pattern)

    if args.verbose:
        print("format:{}".format(s))
        print("pattern:{}".format(pattern))
        print("res:{}".format(res))

    return res


def process(line):
    splitor = args.splitor
    line = line.strip()

    items = line.split(splitor)
    # print(items)
    if args.format:
        s = do_print(args.format, items, line)
        if args.escape:
            s = s.encode().decode('unicode-escape')
        print(s)


def test():
    # test first
    args.splitor = ' '
    args.format = '{1}'
    line = 'websockets       6.0'
    print(line)
    process(line)

    # test last
    args.splitor = ' '
    args.format = '{-1}'
    line = 'websockets       6.0'
    print(line)
    process(line)

    # test other symbol
    args.dolar = True
    args.splitor = ' '
    args.format = '$-1'
    line = 'websockets       6.0'
    print(line)
    process(line)

    return


def main():
    splitor = args.splitor
    args.splitor = splitor.encode('utf8').decode('unicode-escape')

    if args.test:
        test()
        return

    fd = sys.stdin
    for line in fd.readlines():
        if not line:
            break
        process(line)


if __name__ == '__main__':
    main()
