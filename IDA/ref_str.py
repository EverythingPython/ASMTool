# get the reference of string in functions

from idautils import *
from idc import *


def get_ref_from(addr):
    mapping = {}

    xrefs = XrefsFrom(addr)
    for ref in xrefs:
        location = ref.frm
        func_addr = GetFunctionAttr(location, FUNCATTR_START)
        mapping[func_addr] = addr

    return mapping


def get_ref_to(addr):
    funcs = []

    xrefs = XrefsTo(addr)
    for ref in xrefs:
        location = ref.frm
        func_addr = GetFunctionAttr(location, FUNCATTR_START)
        funcs.append(func_addr)

    return funcs


from collections import defaultdict


def main():
    idastr = Strings()
    mapping = defaultdict(set)
    for s in idastr:
        str_addr = s.ea
        funcs = get_ref_to(str_addr)
        for addr in funcs:
            refs = mapping[addr]
            refs.add(s)

    target_func = None
    # target_func = 0x1136a0
    if target_func:
        addr, refs = target_func, mapping[target_func]
        fname = GetFunctionName(addr)
        print('{}\t{:x}\n'.format(fname, addr))
        for s in refs:
            print('\t{:x}\t{}\t{}\n'.format(s.ea, s.ea, str(s).lstrip()))
    else:
        with open('func_string.txt', 'wb+') as fd:
            for addr, refs in mapping.iteritems():
                fname = GetFunctionName(addr)
                fd.write('{}\t{:x}\n'.format(fname, addr))
                for s in refs:
                    fd.write('\t{:x}\t{}\t{}\n'.format(s.ea, s.ea, str(s).lstrip()))


if __name__ == '__main__':
    main()
