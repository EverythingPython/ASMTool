#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
socket server
'''
import socket
import sh,os
import re

import click


@click.command()
@click.option('-s', '--scheme',)
@click.option('-p', '--package',)
@click.argument('extra',nargs=-1)
def main(scheme, package,extra):
    print(extra)
    extra = ['--'+e for e in extra]
    cmd = 'adb shell am start -a android.intent.action.VIEW -d "{}" {} {}'.format(
        scheme, package, ' '.join(extra))
    print(cmd)
    os.system(cmd)


if __name__ == "__main__":
    main()
