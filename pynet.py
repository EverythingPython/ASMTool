# coding=utf-8

import sh
import sys
import os

import socket
import traceback

import time
import hashlib
import requests
import requests_html
from requests_html import HTMLSession


def info(msg):
    print('[*] {}'.format(msg))


def try_nc(ip, port):
    info('nc')

    nc = sh.Command('nc')
    res = nc([ip, port, '-tv', '-w', 4])
    print(res.stdout.decode())
    print(res.stderr.decode())


def try_socket(ip, port):
    info('socket')

    s = socket.create_connection((ip, port))
    try:
        print(s.recv(10))
        s.send(b'test')
        print(s.recv(10))
    except:
        pass
        # s.close()
    
    s.close()


def try_http_get(ip, port):
    info('http')

    session = HTMLSession()
    url = 'http://{}:{}'.format(ip, port)
    print(url)

    para = {
        
    }

    res = session.get(url, **para)
    print(res)
    print(res.status_code)
    print(res.text)
    print(dir(res))

def try_http_post(ip, port):
    info('http')

    session = HTMLSession()
    url = 'http://{}:{}'.format(ip, port)
    print(url)

    para = {
        
    }

    res = session.post(url+'/mnt/sdcard/hackit.txt',data='1'*2048, **para)
    print(res)
    print(res.status_code)
    print(res.text)
    print(dir(res))


def try_http_put(ip, port):
    info('http')

    session = HTMLSession()
    url = 'http://{}:{}/'.format(ip, port)
    print(url)

    para = {
        
    }

    res = session.put(url+'/mnt/sdcard/hackit.txt',data='1'*2048,**para)
    print(res)
    print(res.status_code)
    print(res.text)
    print(dir(res))



def main():
    argv = sys.argv
    if len(argv) < 3:
        print('usage: ./? ip port')

    ip, port = argv[1:3]

    trys = [
        # try_nc,
        try_socket,
        # try_http_get,
        # try_http_post,
        # try_http_put,
    ]

    for func in trys:
        try:
            for _ in range(100):
                func(ip, port)
        except:
            traceback.print_exc()


if __name__ == "__main__":
    main()
