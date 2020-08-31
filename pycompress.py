#!/usr/bin/env python3

"""
Actually, we do not need it - using zsh `z` command is enough.
"""

import sh
import sys, os
from collections import namedtuple
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("-d", "--decompress", help="decompress", action="store_true", dest="decompress")
parser.add_argument("-c", "--compress", help="compress", action="store_true", dest="compress")

# parser.add_argument(nargs=argparse.REMAINDER, dest="value")
parser.add_argument(nargs="*", dest="value")
args = parser.parse_args()

CompressCmd = namedtuple('CompressCmd', ['compress', 'decompress'])


def get_handler(filepath):
    post_dict = {
        '.txt': CompressCmd('compress', 'decompress'),
        '.zip': CompressCmd('zip', 'unzip'),
        '.tar': CompressCmd('', ''),
        '.gz.tar': CompressCmd('', ''),

    }

    filename = os.path.split(filepath)[-1]
    cmds = None
    last_post = ''
    for post in post_dict:
        print(post, filename)
        if filename.endswith(post):
            if post > last_post:
                cmds = post_dict[post]
                last_post = post

    if not cmds:
        raise Exception('unknown post')

    def handler(filepath, decompress=True):
        print(filepath)
        print(cmds)
        if decompress:
            cmd = cmds.decompress
        else:
            cmd = cmds.compress
        print(cmd)
        return

    return handler


def main():
    if not args.value:
        return

    target = args.value.pop()

    handler = get_handler(target)
    if args.compress and args.decompress:
        raise Exception('-d -c cant use together')

    if args.compress:
        handler(target, decompress=False)
    else:
        handler(target, decompress=True)


if __name__ == '__main__':
    main()
