# ASMTool
Some scripts tools for ia32 ( intel 64) assembly language.

## flags.py
a script tool to compute x86 asm flag values and relations.
input: flag value.
output: feasible relations (aka. CC).

## check_jcc.py
using angr (simu exec) and pwntools (asm process), check if the jcc is feasible after spec ins.
input: asm in string.
output: jcc feasible or infeasible.
