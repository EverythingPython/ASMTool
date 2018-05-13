#!/usr/bin/python
import sys


def may_hex(item):
    for i in 'abcdef':
        if i in item:
            return True
    return False


def process_value(item):
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


def print_value(n):
    print("hex:\t{}".format(hex(n)))
    print("dec:\t{}".format(n))


def main():
    args = sys.argv
    if len(args) <= 1:
        print("at least 1 args")
        exit(0)
    # only accept one arg
    item = ''.join(args[1:])
    n = process_value(item)
    print_value(n)


if __name__ == '__main__':
    main()
