# ASMTool
Some tools for binary analyses.

- [ASMTool](#asmtool)
- [Name Rule](#name-rule)
- [Command](#command)
- [Generator](#generator)
- [Binary](#binary)
  - [eflags.py](#eflagspy)
  - [jcc.py](#jccpy)
  - [unicorn_eg.py](#unicorn_egpy)
  - [group](#group)
- [misc](#misc)
  - [misc/vex](#miscvex)
  - [Crypto](#crypto)
  - [DB](#db)
- [Ref](#ref)

# Name Rule
* eg = example.
* pycmd = python version of cmd.
* cmd can go with `-`, but module only go with `_`; use `_` for common case.

# Command
* pyawk, easy work awk in python - I hate the awk escape!
* pyhttp, easy start a http server.
* pysocket, simple test for low level socket.
* pygit-user, easy change git local user.
* pyascii, show ascii code table.
* pyvalue, show value of the given.
* (deprecated) cheatsheet, quick lookup and give the related knowledge.

# Generator
- gen-argparser, give me a argparser statement in python now!
- gen-password, unsafe random password generator


# Binary
## eflags.py
a script tool to compute x86 asm flag values and relations.
input: flag value.
output: feasible relations (aka. CC).

## jcc.py
using angr (simu exec) and pwntools (asm process), check if the jcc is feasible after spec ins.
input: asm in string.
output: jcc feasible or infeasible.

## unicorn_eg.py
simulate asm execution using unicorn.

here is a e.g. but useful too.

## group
- frida/
    All tools base on frida.
    see [APPMon]()
- lief/
    all tools base on LIEF.
- IDA/
- llvm/
- fuzz/
  - [Radamsa](https://github.com/aoh/radamsa): a corpus (test case) generator.

Here we keep an linux executable only.

# misc

## misc/vex
[Vex](): VEX IR library.

only the original header and simple list of all vex ir.

## Crypto
some special encryption algorithm implement in python.
- ssaes: super simplified AES.

## DB
- [SQLiteHelper.py](https://github.com/TomOrth/SQLiteHelper)

> try ORM like `sqlalchemy`

# Ref
- Clang
  - https://github.com/ethanhs/clang
- Frida
  - https://github.com/iddoeldor/frida-snippets
- IDA
  - https://github.com/arizvisa/ida-minsc
  - https://github.com/idapython/src
- Fuzz
  - https://gitlab.com/akihe/radamsa
  - ASAN