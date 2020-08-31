#!/usr/bin/env python
import sh
import sys
import os
import re
import requests_html
from requests_html import HTML, HTMLSession

import argparse
parser = argparse.ArgumentParser(description='python -m SimpleHTTPServer 8080')
parser.add_argument("-p", "--port", help="port", action="store",
                    default=0, type=int, dest="port")
parser.add_argument("-t", "--time", help="timer(s)",
                    action="store", default=0, type=int, dest="time")
parser.add_argument("-n", "--num", help="number",
                    action="store", default=None, type=int, dest="num")
parser.add_argument(nargs=argparse.REMAINDER, dest="value")
args = parser.parse_args()


def text2():
    import sys
    from bs4 import BeautifulSoup

    filename = sys.args[1]
    fd = open(filename)
    soup = BeautifulSoup(fd)
    print(soup.get_text())


def main():
    session = HTMLSession()
    r= session.get('http://www.baidu.com')
    # print(r.text)
    print(r.html.full_text[0:1000])



if __name__ == '__main__':
    main()
