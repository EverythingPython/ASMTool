# coding=utf-8
import os
import sys
from urllib import quote, unquote


def url_encode(data):
    res = quote(data)
    print(res)
    return res


def url_decode(data):
    res = unquote(data)
    print(res)
    return res


def main():
    url_encode('123 123 123')
    url_encode('美国队长')
    res = url_decode('%E7%BE%8E%E5%9B%BD%E9%98%9F%E9%95%BF')
    sys.stdout.flush()


if __name__ == '__main__':
    main()
