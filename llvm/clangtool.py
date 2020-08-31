#!/usr/bin/env python
import sys
import clang.cindex
import pprint

from clang.cindex import Config
from clang.cindex import Cursor
from clang.cindex import CursorKind

libclang = "/usr/lib/llvm-6.0/lib/"
libclang = '/usr/local/Cellar/llvm/6.0.0/lib/'

g_filename = None


def show_token(node):
    ts = node.get_tokens()
    for n in ts:
        print("%s (%s)" % (n.spelling or n.displayname, str(n.kind).split(".")[1]))


def node_children(node):
    return (c for c in node.get_children() if c)


def print_node(node):
    text = node.spelling or node.displayname
    kind = str(node.kind)[str(node.kind).index('.') + 1:]
    return '{} {}'.format(kind, text)


const_int = []
const_str = []
const_float=[]

def visit(cursor):
    location = cursor.location
    file = location.file
    line = location.line
    if file:
        if not file.name == g_filename:
            return
    # print(cursor.get_definition())
    text = cursor.spelling or cursor.displayname
    text = text or ''.join([t.spelling for t in cursor.get_tokens()])
    kind = str(cursor.kind).split(".")[1]
    # print('{} {} {}'.format(line, kind, text))
    # for t in cursor.get_tokens():
    #     print(t.spelling or t.displayname),

    # get literal
    if kind == 'INTEGER_LITERAL':
        const_int.append(text)
    elif kind == 'STRING_LITERAL':
        const_str.append(text)
    elif kind =='FLOATING_LITERAL':
        const_float.append(text)

    for n in cursor.get_children():
        visit(n)

    return


Config.set_library_path(libclang)
index = clang.cindex.Index.create()
# translate unit
if len(sys.argv) > 1:
    g_filename = sys.argv[1]
else:
    g_filename = 'plugin.cpp'

tu = index.parse(g_filename, ['-x', 'c++', '-std=c++11'])
# tu = index.parse('plugin.cpp', ['-x', 'c++', '-std=c++11', '-D__CODE_GENERATOR__'],
#                  options=clang.cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)

show_token(tu.cursor)
visit(tu.cursor)

pprint.pprint(const_int)
pprint.pprint(const_str)
pprint.pprint(const_float)