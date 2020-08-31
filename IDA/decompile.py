"""
comment:
decompile(pattern)
pattern fnmatch like *name*
case-care and search
output is output.cpp in current folder
"""

from idautils import *
from idc import *
from idaapi import *

import idaapi

from fnmatch import fnmatch, fnmatchcase

replace_list = [
    "`typeinfo for'", "`VTT for'", "`vtable for'"
]

def demangle(name):
    """
    translate method signature name (mangle name) to demangle name
    :param name:
    :return:
    """
    res = demangle_name(name, 0)
    if res is None:
        return name
    return res


def do_decompile(addr, filter=lambda x: True):
    func = addr
    name = GetFunctionName(func)
    name = demangle(name)

    if not filter(name):
        return ''

    dedata = idaapi.decompile(func)
    return dedata


def test():
    print('start test')
    pattern = '*main*'

    def filter(name):
        # print(name)

        if fnmatch(name, pattern):
            # print('match {}'.format(name))
            return True
        # print('pass {}'.format(name))
        return False

    addr = 0
    while 1:
        addr = NextFunction(addr)
        if addr == BADADDR:
            break

        # only get the first one for test
        if do_decompile(addr, filter):
            break


def decompile(pattern, output="output.cpp"):
    """

    :param pattern:
    :return:
    """
    print('start decompile')

    def post_process(src):
        for i in replace_list:
            src = src.replace(i, '/*{}*/'.format(i))
        return src

    def filter(name):
        # print(name)

        if fnmatch(name, pattern):
            # print('match {}'.format(name))
            return True
        # print('pass {}'.format(name))
        return False

    fd = open(output, 'w+')

    addr = 0
    while 1:
        addr = NextFunction(addr)
        if addr == BADADDR:
            break
        src = do_decompile(addr, filter)
        if src:
            src = str(src)
            src = post_process(src)
            fd.write(src + '\n\n')
    fd.close()


def main():
    test()


if __name__ == '__main__':
    main()
