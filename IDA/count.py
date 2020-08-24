# comment

from idautils import *
from idc import *
from idaapi import *

from utils import *


def get_ins_class(bin=None, asm=None):
    pass


def count_func_ins(addr):
    count = 1
    ea = NextFunction(addr - 1)
    name = Name(addr)

    ins_count = 0
    for e in FuncItems(ea):
        ins_count += 1
    print('function:{} has {} ins'.format(name, ins_count))


def count_all_ins(start=0):
    addr = start
    count = 0

    ea = NextFunction(addr)
    print(hex(ea))
    while ea != BADADDR:
        next_ea = NextFunction(ea)
        if next_ea == ea:
            break
        ea = next_ea
        for e in FuncItems(ea):
            count += 1
    print(count)
    return count


def output_all_asm_ins(start=0):
    addr = start
    count = 0
    with open('/Users/fengyouzheng/Desktop/ins.txt', 'w') as fd:
        while addr!=BADADDR:
            e = NextHead(addr)
            if idaapi.isCode(idaapi.getFlags(e)):
                fd .write('{},{}'.format(hex(e), GetMnem(e).lower()))
                fd.write('\n')
            addr = e

def output_all_function_ins(start=0):
    addr = start
    count = 0

    ea = NextFunction(addr)
    print(hex(ea))
    with open('/Users/fengyouzheng/Desktop/ins.txt', 'w') as fd:
        while ea != BADADDR:
            next_ea = NextFunction(ea)
            if next_ea == ea:
                break
            ea = next_ea
            for e in FuncItems(ea):
                fd .write('{},{}'.format(hex(e), GetMnem(e).lower()))
                fd.write('\n')


def count_func(start=None, end=None):
    addr = start if start else 0
    last_addr = end if end else get_end()

    count = 0
    if not start and not end:
        for segea in Segments():
            segname = SegName(segea)
            print(segname)
            for funcea in Functions(segea, SegEnd(segea)):
                count += 1
    else:
        ea = NextFunction(addr)
        print(hex(ea))
        while ea < last_addr:
            next_ea = NextFunction(ea)
            if next_ea == ea:
                break
            ea = next_ea
            count += 1
    print(count)


print('hello')
count_func(0x33f4)
count_func(1)


def main():
    pass


if __name__ == '__main__':
    main()
