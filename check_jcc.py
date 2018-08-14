# coding=utf-8

import angr
import pyvex
from angr import SimState

import unicorn
from unicorn import *
from unicorn.x86_const import *

import pwn

import archinfo

import logging.config
import logging.handlers
import logging

config = {
    "version": 1,
    "disable_existing_loggers": True,
    "root": {
        "level": "WARNING",
        "propagate": "no",
        "handlers": []
    }
}
logging.config.dictConfig(config)

verbose = 1

# bit offset of each flag
eflags = {
    'SF': 7,
    'ZF': 6,
    'CF': 0,
    'OF': 11,
    'DF': 10,

}
regs = [
    'eax', 'ebx', 'ecx', 'edx',
    'esp', 'ebp', 'esi', 'edi',
    'eip',
    'eflags',
]

# place the jcc pair by pair
jcc_s = [
    'jz', 'jnz',  # 0, ==
    'ja', 'jb',  # uint

    'jg', 'jl',  # int
    'js', 'jns',
    'jc', 'jnc',  # carry, borrow

    'je',  # jz

]


class Checker:
    def __init__(self):
        self.state = None

    def print_reg(self):
        raise NotImplementedError

    def print_flag(self):
        raise NotImplementedError

    def print_ctx(self):
        if verbose:
            self.print_reg()
            self.print_flag()

    def check_jcc(self):
        raise NotImplementedError

    def run_bin(self, bin_code):
        raise NotImplementedError

    def run_asm(self, asm_code):
        bin_code = self.assemble(asm_code)
        state = self.run_bin(bin_code)
        return state

    @staticmethod
    def assemble(asm_code):
        return pwn.asm(asm_code)


class UC_Checker(Checker):
    def __init__(self):
        self.state = None
        self.engine = Uc(UC_ARCH_X86, UC_MODE_32)

    def check_jcc(self, asm_code, jcc=None):
        # TODO: this does not work now!
        """

        :param state:
        :param jcc:
        :return:
        """

        self.state = self.run_asm(asm_code)

        state = self.state
        engine = self.engine

        self.print_ctx()

        eflagid = getattr(unicorn.x86_const, "UC_X86_REG_EFLAGS")
        eflag = self.state.reg_read(eflagid)

        import flags 
        checker = flags.init()
        print(checker.getRelation(eflag))

        # feasible = []
        # infeasible = []
          
        # print("feasible:\n{}".format('\t'.join(feasible)))
        # print("infeasible:\n{}".format('\t'.join(infeasible)))

    def run_bin(self, bin_code):
        engine = self.engine

        addr = 0x100000

        engine.mem_map(addr, 2 * 1024 * 1024)
        engine.mem_write(addr, bin_code)

        engine.emu_start(addr, addr + len(bin_code))

        eflag = engine.reg_read(UC_X86_REG_EFLAGS)
        print(("EFLAG: {}".format(eflag)))
        return engine

    def print_reg(self):
        if verbose:
            for name in regs:
                regid = getattr(unicorn.x86_const, "UC_X86_REG_{}".format(name.upper()))
                regval = self.state.reg_read(regid)
                print(("{}:{}".format(name, regval)))

    def print_flag(self):
        if verbose:
            eflagid = getattr(unicorn.x86_const, "UC_X86_REG_EFLAGS")
            eflag = self.state.reg_read(eflagid)
            for name, site in list(eflags.items()):
                print(("{}:{}".format(name, (eflag & 1 << site) >> site)))


class Angr_Checker(Checker):

    def __init__(self):
        self.engine = angr.SimEngineVEX()

        self.add_options = {
            angr.options.INITIALIZE_ZERO_REGISTERS,
            angr.options.CONCRETIZE,
        }

    def run_bin(self, bin_code):

        add_options = self.add_options
        engine = self.engine

        irsb = pyvex.IRSB(bin_code, 0x100000, archinfo.ArchX86(), len(bin_code))
        if verbose:
            irsb.pp()

        state = SimState(arch='X86', add_options=add_options, )

        engine.process(state, irsb, inline=True)

        return state

    def print_reg(self):
        if verbose:

            state = self.state

            for name in regs:
                regval = state.regs.__getattr__(name)
                print(("{}:{}".format(name, regval)))

    def print_flag(self):
        if verbose:
            state = self.state

            eflag = state.regs.eflags
            for name, site in list(eflags.items()):
                print(("{}:{}".format(name, eflag[site])))

    def check_jcc(self, asm_code, jcc=None):
        # TODO: this does not work now!
        """

        :param state:
        :param jcc:
        :return:
        """

        self.state = self.run_asm(asm_code)

        state = self.state
        add_options = self.add_options
        engine = self.engine

        feasible = []
        infeasible = []
        if jcc:
            pending = {jcc}
        else:
            pending = jcc_s

        for jcc in pending:
            asm_code = 'target:; {} target; '.format(jcc)
            jmp_code = pwn.asm(asm_code)
            code_size = len(jmp_code)

            addr = state.regs.eip.args[0]
            irsb = pyvex.IRSB(jmp_code, addr, archinfo.ArchX86(), code_size)
            # irsb.pp()

            # we simulate the ins and get the successor state
            simsucc = engine.process(state, irsb, inline=False)
            succ = simsucc.successors[0]

            # judge the jcc by the successor state
            eip = succ.regs.eip.args[0]
            if eip == addr:
                feasible.append(jcc)
            elif eip == addr + code_size:
                infeasible.append(jcc)
            else:
                print("impossible eip")
                raise Exception("impossible eip!")

        print(("feasible:\n{}".format('\t'.join(feasible))))
        print(("infeasible:\n{}".format('\t'.join(infeasible))))


def excption_0():
    import claripy

    ins_code = "mov eax,-1 ; test eax,eax"
    address = 0x76fcbcfe

    encoding = pwn.asm(ins_code)
    count = len(encoding)
    print((str(encoding)))
    print(count)

    add_options = {angr.options.NO_SYMBOLIC_SYSCALL_RESOLUTION,
                   angr.options.LAZY_SOLVES,
                   angr.options.INITIALIZE_ZERO_REGISTERS,
                   angr.options.SIMPLIFY_REGISTER_WRITES,
                   angr.options.SIMPLIFY_MEMORY_WRITES,
                   # angr.options.CONCRETIZE,
                   # angr.options.FAST_MEMORY
                   }

    bc_arr = ""
    bc_arr = encoding

    irsb = pyvex.IRSB(bc_arr, 0x76fcbcfe, archinfo.ArchX86(), len(bc_arr))

    state = SimState(arch='X86', add_options=add_options)
    state.regs.eax = 0x5a4d
    state.regs.esi = 0x753e0001
    state.regs.esp = 0x12f8c0
    state.regs.eip = 0x76fcbcfe

    taint_len = 0x8000
    # taint_len = 0xd4000

    state.memory.store(0x753e0000, claripy.BVS(
        "TAINT_MapView", taint_len * 8), endness="Iend_LE")

    engine = angr.SimEngineVEX()

    irsb.pp()
    engine.process(state, irsb, inline=True)


if __name__ == '__main__':
    asm = "mov eax,1 ; cmp eax,0xffffffff;"
    asm = "mov eax,1 ; cmp eax,1;"
    # asm = "mov eax,0x0 ; sub eax,1;"
    print(asm)

    ucc = UC_Checker()
    ucc.check_jcc(asm)

    # ac = Angr_Checker()
    # ac.check_jcc(asm)

    # check_jcc(state, 'ja')
    # check_jcc(state, 'jg')
    # check_jcc(state,)
