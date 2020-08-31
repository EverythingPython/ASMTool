"""
idat -B "target_binary"
"C:\Program Files\IDA 7.0\idat64.exe"  -B  "C:\Users\test\Desktop\cpp_cast"

idat -S"script" "idb"
"C:\Program Files\IDA 7.0\idat64.exe"  -S"C:\Users\test\Desktop\myida.py"  "C:\Users\test\Desktop\cpp_cast.i64"

WARNING:
任何错误都会导致程序进入window视窗，调试阶段务必留意错误；
实际使用时，务必try except main
"""
import traceback

from idautils import *
from idc import *
from idaapi import *
import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry

import idaapi

# FIXME: 需要额外给定路径
path = 'C:\\Users\\test\\Desktop\\'


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

    code = idaapi.decompile(func)
    return name, code


def decompile(addr=0):
    while 1:
        addr = NextFunction(addr)
        if addr == BADADDR:
            break

        # only get the first one for test
        name, code = do_decompile(addr, filter)
        print(name)
        with open('{}/{}.cpp'.format(path, name), 'w') as fd:
            print(code)
            print(type(code))
            fd.write(str(code))
        break


def load_decompiler():
    ALL_DECOMPILERS = {
        ida_idp.PLFM_386: ("hexrays", "hexx64"),
        ida_idp.PLFM_ARM: ("hexarm", "hexarm64"),
        ida_idp.PLFM_PPC: ("hexppc", "hexppc64"),
    }
    pair = ALL_DECOMPILERS.get(ida_idp.ph.id, None)
    if pair:
        decompiler = pair[1 if ida_ida.cvar.inf.is_64bit() else 0]
        if ida_loader.load_plugin(decompiler) and ida_hexrays.init_hexrays_plugin():
            return True
        else:
            print("Couldn't load or initialize decompiler: \"%s\"" % decompiler)
    else:
        print("No known decompilers for architecture with ID: %d" % ida_idp.ph.id)


def main():
    # turn on coagulation of data in the final pass of analysis
    # set_inf_attr(INF_AF, get_inf_attr(INF_AF) | AF_DODATA | AF_FINAL);
    # .. and plan the entire address space for the final pass
    #auto_mark_range(0, BADADDR, AU_FINAL);

    print('waiting for the ida auto')
    validate_idb_names()
    auto_wait()
    print('complete ida auto')

    # create the assembler file
    dbfile = get_idb_path()
    print('dbfile: %s' % dbfile)

    # try:
    #     filepath = dbfile[0:-4] + ".asm"
    #     gen_file(OFILE_ASM, filepath, 0, BADADDR, 0)
    # except:
    #     traceback.print_exc()

    msg('Decompile')
    # must load decompiler
    load_decompiler()
    # do decompile
    decompile()


if __name__ == "__main__":
    msg('Hello IDA')
    main()
    msg("All done, exiting...\n")
    qexit(0)
