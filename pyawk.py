#!/usr/bin/env python3
import re
import os
import sys
import logging

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-F", "--split", help="splitor, must escape code",
                    action="store", default=' ', type=str, dest="splitor")
parser.add_argument("-p", "--format", help="print data in format, default use {{}}, -h to know others",
                    action="store", default='', type=str, dest="format")
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

    # 0 as whole line
    pattern = list(items)
    pattern.insert(0, line)

    for i in range(n):
        # replace id
        # positive from 0 to n-1
        # negative to positive

        if args.dolar:
            s = s.replace('${}'.format(i), '{{{}}}'.format(i))
            s = s.replace('${}'.format(-(i + 1)),'{{{}}}'.format(n - 1 - i))
        elif args.percent:
            s = s.replace('%{}'.format(i), '{{{}}}'.format(i))
            s = s.replace('%{}'.format(-(i + 1)), '{{{}}}'.format(n - 1 - i))
        else:
            #s = s.replace('{{{}'.format((i + 1)), '{{{}'.format(i))
            s = s.replace('{{{}'.format(-(i + 1)), '{{{}'.format(n - 1 - i))

    if args.verbose:
        print("res:{}".format(s))
        print("pattern:{}".format(pattern))
    
    # do format    
    s = s.format(*pattern)
    return s


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


def main():
    splitor = args.splitor
    args.splitor = splitor.encode('utf8').decode('unicode-escape')

    if 0:
        args.splitor = ' '
        args.format = '{1}'
        line = 'websockets       6.0'
        process(line)
        return

    fd = sys.stdin
    for line in fd.readlines():
        if not line:
            break
        process(line)


if __name__ == '__main__':
    main()
