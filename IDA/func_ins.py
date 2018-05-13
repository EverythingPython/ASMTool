# comment

from idautils import *
from idc import *
from idaapi import *


def get_ins_class(bin=None, asm=None):
    pass


def get_ins(addr):
    ea = NextFunction(addr - 1)
    name = Name(addr)

    ins_count = 0
    for e in FuncItems(ea):
        ins_count += 1
    print('function:{} has {} ins'.format(name, ins_count))


def main():
    pass


if __name__ == '__main__':
    main()
