# comment

import sys

sys.path.append('IDA')

from idautils import *
from idc import *
from idaapi import *


def get_disasm(addr):
    ea = NextFunction(addr - 1)
    name = Name(addr)

    start = GetFunctionAttr(ea, FUNCATTR_START)
    end = GetFunctionAttr(ea, FUNCATTR_END)

    for item in FuncItems(start):
        # print(item)
        ins_size = ItemSize(item)
        ins_hex = get_bytes(item, ins_size)
        ins_hex = map(lambda x: hex(ord(x)), ins_hex)
        for i in ins_hex:
            print('{},'.format(i)),



        addr = item
        disasm = GetDisasm(addr)
        # print(hex)
        print("{}#{}".format('\t'*5,disasm))


get_disasm(0x1eb0)


def main():
    pass


if __name__ == '__main__':
    main()
