import sys
import os

import pprint

import logging.config
import logging.handlers
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s %(filename)s[line:%(lineno)d]  %(message)s',
    # format='%(levelname)s %(asctime)s %(filename)s[line:%(lineno)d]  %(message)s',
    datefmt='%a, %d %b %Y %H:%M:%S',
)

logger = logging.getLogger('flags')
logger.setLevel(logging.INFO)
logging = logger


# try to use a tree to store all flags, since some relations are related

# target flag set
CF = int(1 << 0)
PF = int(1 << 2)
AF = int(1 << 4)
ZF = int(1 << 6)
SF = int(1 << 7)
OF = int(1 << 11)

# 32...0
flagDict = dict()

flagDict["cf"] = CF
# flagDict["pf"]=PF
# flagDict["af"]=AF
flagDict["zf"] = ZF
flagDict["sf"] = SF
flagDict["of"] = OF

targetFlag = 0
logging.debug(flagDict)
for i in flagDict:
    targetFlag = targetFlag | flagDict[i]
    r = 65535 - flagDict[i]
    logging.debug(i, "=", bin(flagDict[i]), " and reverse=", r, "=", bin(r))

# WARNING: positive flag init as 0xff..ff, just a representation
CF = 65535 | int(1 << 0)
PF = 65535 | int(1 << 2)
AF = 65535 | int(1 << 4)
ZF = 65535 | int(1 << 6)
SF = 65535 | int(1 << 7)
OF = 65535 | int(1 << 11)

# target flag reset no matter what others
rCF = 65535 ^ int(1 << 0)
rPF = 65535 ^ int(1 << 2)
rAF = 65535 ^ int(1 << 4)
rZF = 65535 ^ int(1 << 6)
rSF = 65535 ^ int(1 << 7)
rOF = 65535 ^ int(1 << 11)

# Relations
EQ_RELATION = "EQ_RELATION"
NE_RELATION = "NE_RELATION"
SGT_RELATION = "SGT_RELATION"
SGE_RELATION = "SGE_RELATION"
SLT_RELATION = "SLT_RELATION"
SLE_RELATION = "SLE_RELATION"
UGT_RELATION = "UGT_RELATION"
UGE_RELATION = "UGE_RELATION"
ULT_RELATION = "ULT_RELATION"
ULE_RELATION = "ULE_RELATION"


from collections import defaultdict
jcc_map = defaultdict(lambda: set())

# the relations depend on flags
# both F set by or |
# both rF reset by and &
# rF with F, we can ignore F for rF must include other F
# others just do logically
listReFlag = [
    (["zf"], ZF, EQ_RELATION),

    (["zf"], rZF, NE_RELATION),

    # rZF OF SF, but rZF include others
    (["zf"], rZF, SGT_RELATION),
    (["zf", "sf", "of"], rZF & rSF & rOF, SGT_RELATION),

    (["sf", "of"], SF & OF, SGE_RELATION),
    (["sf", "of"], rSF & rOF, SGE_RELATION),

    (["sf", "of"], SF & rOF, SLT_RELATION),
    (["sf", "of"], rSF & OF, SLT_RELATION),

    (["zf"], ZF, SLE_RELATION),
    (["sf", "of"], SF & rOF, SLE_RELATION),
    (["sf", "of"], rSF & OF, SLE_RELATION),

    (["cf", "zf"], rCF & rZF, UGT_RELATION),
    (["cf"], rCF, UGE_RELATION),

    (["cf"], CF, ULT_RELATION),

    (["cf"], CF, ULE_RELATION),
    (['zf'], ZF, ULE_RELATION),
]

mapReFlag = dict()

for (need, value, name) in listReFlag:
    mapReFlag[value] = name
    # logging.debug item
    logging.debug(need, name, "=", bin(value), "=", value)

    jcc_map[name]


# set the jcc info, never add negative e.g. jna
for name in jcc_map:
    jcc = set()

    # get from name
    t = name.split('_')[0]

    if t.startswith('S'):
        if 'G' in t:
            jcc.add('jg')
        if 'L' in t:
            jcc.add('jl')
    elif t.startswith('U'):
        if 'G' in t:
            jcc.add('ja')
        if 'L' in t:
            jcc.add('jb')

    if 'NE' in t:
        jcc.add('jne')
    elif 'E' in t:
        temp = set()
        for i in jcc:
            temp.add(i+'e')
        jcc.add('je')
        jcc.update(temp)

    jcc_map[name] = jcc

logging.debug(jcc_map)


def getFlag(name):
    return flag[name]


def getTargetFlag(flag):
    res = flag & targetFlag
    return res


def getMask(need):
    # get the flag we need as mask
    mask = 0
    for i in need:
        mask = mask | flagDict[i]
    return mask


class FlagCheck():
    def __init__(self):
        self.flags = []

    def getJcc(self, flag):
        # get the target flag first, and check if it suits
        res = set()
        for (mask, target, name) in self.flags:

            # mask flag and value
            # if they are same , them it is
            if (mask & flag) == target:
                # print name,bin(val)
                res.update(jcc_map[name])

        logging.debug('flag {} = {} may mean:{}'.format(flag, bin(flag), res))
        return res

    def getRelation(self, flag):
        # get the target flag first, and check if it suits
        res = set()
        for (mask, target, name) in self.flags:

            # mask flag and value
            # if they are same , them it is
            if (mask & flag) == target:
                # print name,bin(val)
                res.add(name)
        logging.debug('flag {} = {} may mean:{}'.format(flag, bin(flag), res))
        return res

    def isRelation(self, flag, name):
        res = self.getRelation(flag)
        logging.debug('flag {} = {} match:{}'.format(flag, bin(flag), res))
        if name in res:
            return True
        else:
            return False


def test_relation(checker):
    print('Test report as bellow:')
    print(checker.getRelation(SF | OF))
    # print getRelation(CF | getFlag("sf")|  getFlag("of"))
    print(checker.isRelation(518, SGE_RELATION))
    print(checker.getRelation(ZF | SF | OF))
    print(checker.isRelation(ZF | SF | OF, UGE_RELATION))


def init():
    from collections import namedtuple

    Flag = namedtuple('flag', ['mask', 'target', 'name'])

    flags = []
    logging.info(
        "Use mask with flag, if maskedflag is target, then it suit the relation")
    logging.debug("mask\ttarget\tname")
    for (need, val, name) in listReFlag:
        mask = getMask(need)
        target = mask & val
        logging.debug("{}\t, {}\t, {}" .format(mask, target, name))
        # print "{%s,%s,%s}," %(bin(mask), bin(mask & val) , name)
        flags .append(Flag(mask, target, name))
    logging.debug(pprint.pformat(flags))

    checker = FlagCheck()
    checker.flags = flags
    return checker


def main():
    checker = init()
    test_relation(checker)


if __name__ == '__main__':
    main()
