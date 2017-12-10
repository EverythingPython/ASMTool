import os,sys
sys.path.append('./')
sys.path.append('../')

from check_jcc import *

asm = "mov eax,-1 ; test eax,eax"
print asm
run_asm(asm)

asm = "mov eax,1 ; test eax,eax"
print asm
run_asm(asm)

asm = "mov eax,0 ; test eax,eax"
print asm
run_asm(asm)
