# ASMTool
Some tools for binary analyses.

- [ASMTool](#asmtool)
- [Name Rule](#name-rule)
- [Command](#command)
- [Binary](#binary)
    - [flags.py](#flagspy)
    - [check_jcc.py](#checkjccpy)
    - [unicorn_eg.py](#unicornegpy)
    - [frida/](#frida)
    - [lief/](#lief)
    - [IDA/](#ida)
    - [llvm/](#llvm)
    - [fuzz/](#fuzz)
- [misc](#misc)
    - [misc/vex](#miscvex)
    - [Crypto](#crypto)
    - [DB](#db)

# Name Rule
* eg = example.
* pycmd = python version of cmd.
* cmd can go with `-`, but module only go with `_`; use `_` for common case.

# Command
* pyawk, easy work awk in python - I hate the awk escape!
* pyhttp, easy start a http server.
* pysocket, simple test for low level socket.
* pygit-user, easy change git local user.
* gen-argparser, give me a argparser statement in python now!
* ascii, show ascii code table.
* value, show value of the given.
* cheatsheet, quick lookup and give the related knowledge.


# Binary
## flags.py
a script tool to compute x86 asm flag values and relations.
input: flag value.
output: feasible relations (aka. CC).

## check_jcc.py
using angr (simu exec) and pwntools (asm process), check if the jcc is feasible after spec ins.
input: asm in string.
output: jcc feasible or infeasible.

## unicorn_eg.py
simulate asm execution using unicorn.

here is a e.g. but useful too.

## frida/
All tools base on frida.
* 

## lief/
all tools base on LIEF.


## IDA/
IDA

## llvm/

## fuzz/
* radamsa
[Radamsa](https://github.com/aoh/radamsa): a corpus (test case) generator.

Here we keep an linux executable only.

# misc


## misc/vex
[Vex](): VEX IR library.

only the original header and simple list of all vex ir.

## Crypto
some special encryption algorithm implement in python.
* ssaes: super simplified AES.

## DB
* [SQLiteHelper.py](https://github.com/TomOrth/SQLiteHelper)