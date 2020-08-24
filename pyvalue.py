#!/usr/bin/env python3
import sys
import argparse
from string import ascii_letters

def may_hex(item):
    for i in 'abcdef':
        if i in item:
            return True
    return False


def process_int(item):
    item = item.lower()
    if '0x' in item:
        # 0x123
        n = int(item, 16)
    elif 'h' == item[-1]:
        # 123ah
        n = int(item[0:-1], 16)
    elif may_hex(item):
        # 12af
        n = int(item, 16)
    else:
        n = int(item, 10)

    return n

def process_ip(s:str):
    try:
        h = None
        try:
            h = int(s,16)
        except:
            pass
        try:
            h = int(s)
        except:
            pass
        if h:
            res = []
            for i in range(6):
                t = h & 255
                h >>= 8
                res.insert(0,t)
            return '.'.join([str(i) for i in res])
    except:
        pass
    return None


def process_str(s):
    upper = s.upper()
    if upper.startswith('0X'):
        upper = upper[2:]
        res = upper.decode('hex')
        return res
    else:
        return s


def print_int(n):
    print("hex:\t{}".format(hex(n)))
    print("dec:\t{}".format(n))
    print("ascii:\t{}".format(chr(n) if 0 <= n <= 255 else 'char overflow'))
    print("ip:\t{}".format(process_ip(n)))

def print_str(n):
    print("int:\t{}".format(ord(n)))
    print("hex:\t{}".format(n.encode('hex')))
    hexstr = [hex(ord(i)) for i in n]
    print("hex:\t{}".format(hexstr))
    print("hex:\t{}".format(' '.join(hexstr)))
    print("str:\t{}".format(n))
    print("len:\t{}".format(len(n)))


def parse_opt():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--string", help="give string type", action="store_true", dest="string")
    parser.add_argument(nargs=argparse.REMAINDER, dest="value")
    args = parser.parse_args()
    return args


def main():
    args = sys.argv
    # if len(args) <= 1:
    #     print("at least 1 args")
    #     exit(0)

    args = parse_opt()
    print(args)

    # only accept one arg
    value = args.value
    if args.string:
        for item in value:
            n = process_str(item)
            print_str(n)
    else:
        for item in value:
            # item = ''.join(args[1:])
            n = process_int(item)
            print_int(n)


if __name__ == '__main__':
    main()
