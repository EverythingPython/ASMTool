import os, sys
import  logging
sys.path.append('./')
sys.path.append('../')

from check_jcc import *
logging.root.setLevel(logging.CRITICAL)

asm = "mov eax,-1 ; test eax,eax"
print(asm)
s=run_asm(asm)
check_jcc(s)

asm = "mov eax,1 ; test eax,eax"
print(asm)
s=run_asm(asm)
check_jcc(s)

asm = "mov eax,0 ; test eax,eax"
print(asm)
s=run_asm(asm)
check_jcc(s)
