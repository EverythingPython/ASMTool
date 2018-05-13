# coding=utf-8
import angr
from angr import SimState
import pwn
import pyvex
import claripy
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

verbose = False

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

pwn.context.log_level = logging.INFO
angr.loggers.default_level = logging.INFO

add_options = {
    angr.options.INITIALIZE_ZERO_REGISTERS,
    angr.options.CONCRETIZE,
}
engine = angr.SimEngineVEX()

# place the jcc pair by pair
jcc_list = [
    'jz', 'jnz',  # 0, ==
    'ja', 'jb',  # uint

    'jg', 'jl',  # int
    'js', 'jns',
    'jc', 'jnc',  # carry, borrow

    'je',  # jz

]


def check_jcc(state, jcc=None):
    # TODO: this does not work now!
    """

    :param state:
    :param jcc:
    :return:
    """
    feasible = []
    infeasible = []
    if jcc:
        pending = [jcc]
    else:
        pending = jcc_list

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
            print "impossible eip"
            raise Exception("impossible eip!")

    print "feasible:\n{}".format('\t'.join(feasible))
    print "infeasible:\n{}".format('\t'.join(infeasible))


def print_reg(state):
    if verbose:
        for name in regs:
            print "{}:{}".format(name, state.regs.__getattr__(name))


def print_flag(state):
    if verbose:
        for name, site in eflags.iteritems():
            print "{}:{}".format(name, state.regs.eflags[site])


def print_ctx(state):
    if verbose:
        print_reg(state)
        print_flag(state)


def run_asm(asm_code):
    bin_code = pwn.asm(asm_code)
    state = run_bin(bin_code)
    return state


def run_bin(bin_code):
    irsb = pyvex.IRSB(bin_code, 0x100000, archinfo.ArchX86(), len(bin_code))
    if verbose:
        irsb.pp()

    state = SimState(arch='X86', add_options=add_options)

    engine.process(state, irsb, inline=True)

    return state


def excption_0():
    ins_code = "mov eax,-1 ; test eax,eax"
    address = 0x76fcbcfe

    encoding = pwn.asm(ins_code)
    count = len(encoding)
    print str(encoding)
    print count

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
    print asm
    state = run_asm(asm)
    print_ctx(state)
    check_jcc(state)
# check_jcc(state, 'ja')
# check_jcc(state, 'jg')
# check_jcc(state,)
