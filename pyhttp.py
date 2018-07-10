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
                    action="store", default=0, type=int, dest="num")                
parser.add_argument(nargs=argparse.REMAINDER, dest="value")
args = parser.parse_args()


def local_ip():
    res = sh.ifconfig().stdout
    # print(res)
    ip = None
    found = re.findall(r'inet ([0-9\.]+[0-9]+)', res)
    for m in found:
        print(m)
        # print(m.groups())
        # print(m.group(1))
        # ip = m.group(1)
    ip = found[args.num]
    return ip    

print('python -m SimpleHTTPServer 8080')

port = args.port
os.system('ls')
print('port {}'.format(port))

ip = local_ip()

print('start http server at:\n{}:{}'.format(ip, port))
if args.value:
    for i in args.value:
        print('may wish to visit:\n{}:{}/{}'.format(ip, port, i))
sys.stdout.flush()

handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = SocketServer.TCPServer(("", port), handler)
try:
    httpd.serve_forever()
except:
    print('stop http server')
