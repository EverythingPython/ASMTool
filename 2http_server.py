#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import sh
import sys
import os
import re
import SimpleHTTPServer
import SocketServer
import json

DEFAULT_PORT = 9001

import argparse
parser = argparse.ArgumentParser(description='python -m SimpleHTTPServer 8080')
parser.add_argument("-p", "--port", help="port", action="store",
                    default=DEFAULT_PORT, type=int, dest="port")
parser.add_argument("-t", "--time", help="timer(s)",
                    action="store", default=0, type=int, dest="time")
parser.add_argument("-n", "--num", help="number",
                    action="store", default=None, type=int, dest="num")
parser.add_argument(nargs=argparse.REMAINDER, dest="value")
args = parser.parse_args()


def get_ip():
    res = sh.ifconfig().stdout
    found = re.findall(r'inet ([0-9\.]+[0-9]+)', res)
    for n, ip in enumerate(found):
        print('{} - {}'.format(n, ip))
        # print(m.groups())
        # print(m.group(1))
        # ip = m.group(1)
    if args.num is None:
        # give a default one
        ret = found[0]
        for ip in found:
            # ignore local
            if ip == '127.0.0.1':
                continue
            else:
                ret = ip
                break
    else:
        ret = found[args.num]

    return ret


def gen_token(n=19):
    import random

    res = ''
    for i in range(n):
        tmp = random.randint(0, 16)
        ch = hex(tmp)[-1]
        res += ch

    return res


class UserDefHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def createHTML(self):
        self.wfile.write('hello')

    def do_GET(self):
        print("GET", self.headers)
        self.createHTML()

    @staticmethod
    def gen_data():
        data = {
            "msgtype": "text",
            "text": {
                "content": "我就是我, @ptt6gbq @17681800905 是不一样的烟火"
            },
            "at": {
                "atMobiles": [
                    "17681800905"
                ],
                "atDingtalkIds": [
                    "ptt6gbq"
                ],
                "isAtAll": False
            }
        }
        return json.dumps(data, ensure_ascii=True)

    def do_POST(self):
        print("POST", self.headers)
        length = int(self.headers.getheader('content-length'))
        token = self.headers.getheader('token')
        body = self
        print("body: {}".format(body))
        if token == '30b68fae4d03a1acdec':
            qs = self.rfile.read(length)
            data = self.gen_data()
            self.send_response(200)
            # send_header("Welcome", "Contect")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(data)


def main():
    print('token: {}'.format(gen_token()))

    print('e.g. python -m SimpleHTTPServer 8080')

    port = args.port
    print('port {}'.format(port))

    ip = get_ip()
    print('start http server at:\n{}:{}'.format(ip, port))
    sys.stdout.flush()

    # set files
    if not args.value:
        print(os.listdir('.'))
    else:
        for i in args.value:
            print('may wish to visit:\n{}:{}/{}'.format(ip, port, i))
    sys.stdout.flush()

    # http server
    handler = UserDefHandler
    httpd = SocketServer.TCPServer(("", port), handler)
    try:
        print(handler.gen_data())
        # return
        httpd.serve_forever()
    except:
        print('stop http server')


if __name__ == '__main__':
    main()
