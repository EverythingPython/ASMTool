from idautils import *
from idc import *
from idaapi import *

def get_end():
    last_addr = 0
    for segea in Segments():
        segend = SegEnd(segea)
        last_addr = segend if segend > last_addr else last_addr
    return last_addr


