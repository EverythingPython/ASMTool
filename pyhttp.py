#!/usr/bin/env python
import sh
import sys
import os
import re
import SimpleHTTPServer
import SocketServer

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
        print('{} - {}'.format(n,ip))
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


def main():
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
    handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(("", port), handler)
    try:
        httpd.serve_forever()
    except:
        print('stop http server')


if __name__ == '__main__':
    main()
