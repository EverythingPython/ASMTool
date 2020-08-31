#!/usr/bin/env python3
# coding=utf-8
import os
import sys
import requests
import json
from queue import Queue
import urllib.request as urllib
import time

from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Pool
from requests_html import HTMLSession


def download(url, package):
    if os.path.exists(package):
        print('exist, ignore')
        return
    print(url)
    cmd = 'curl -o {} -L {} '.format(package, url)
    print(cmd)
    os.system(cmd)
    print('download completed')


def get_content_size(url, proxy=None):
    """
    通过head方法，仅获取header，并从中抽取必要信息，而不必大量IO，获取content
    :param url:
    :param proxy:
    :return:
    """
    res = requests.head(url, timeout=10, allow_redirects=False)
    size = res.headers['Content-Length']
    return int(size)


def get_redirect_url(url, try_count=1):
    """
    禁止自动处理重定向，并从重定向的location中获取目标url
    :param url:
    :param try_count:
    :return:
    """
    res = requests.get(url, timeout=10, allow_redirects=False)
    print(res.headers)
    print(res.url)
    try:
        location = res.headers['location']
        print(location)
    except:
        location=  None
    try:
        filename = res.headers['Content-Disposition']
        print(filename)

        if "''" in filename:
            # e.g. filename*=utf''filename.txt
            filename = filename.split('\'')[-1]
        else:
            # e.g. filename=filename.txt
            filename = filename.split('=')[-1]

        filename = urllib.unquote(filename)
    except:
        filename = None

    return location or filename




def main():
    argv = sys.argv
    url = argv[1]
    # url = ' http://11.164.62.148:5000/download/f055b71da23001e4d6630a865d351ec138620c93f7c2654c81d1e07207a69f56_1008292'
    print(argv)

    # s= 'filename*=utf''filename.txt'
    # print(urllib.url2pathname(s))
    # print(urllib.unquote(s))
    # exit()

    print('url %s', url)
    location = get_redirect_url(url)
    print('location %s', location)
    res = download(url, location)


if __name__ == "__main__":
    main()
