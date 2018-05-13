import sys
import os

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
print flagDict
for i in flagDict:
    targetFlag = targetFlag | flagDict[i]
    r = 65535 - flagDict[i]
    print i, "=", bin(flagDict[i]), " and reverse=", r, "=", bin(r)


CF = 65535 | int(1 << 0)
PF = 65535 | int(1 << 2)
AF = 65535 | int(1 << 4)
ZF = 65535 | int(1 << 6)
SF = 65535 | int(1 << 7)
OF = 65535 | int(1 << 11)

# target flag reset no matter what others
rCF = 65535 - int(1 << 0)
rPF = 65535 - int(1 << 2)
rAF = 65535 - int(1 << 4)
rZF = 65535 - int(1 << 6)
rSF = 65535 - int(1 << 7)
rOF = 65535 - int(1 << 11)

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
    (["cf", "zf"], CF | ZF, ULE_RELATION),
]

mapReFlag = dict()


for (need, val, name) in listReFlag:
    mapReFlag[val] = name

    # print item
    print need, name, "=", bin(val), "=", val


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

# get the target flag first, and check if it suits


def getRelation(flag):
    res = []
    print bin(flag)
    print bin(flag)
    for (need, val, name) in listReFlag:
        mask = getMask(need)

        # mask flag and value
        # if they are same , them it is
        if (mask & flag) == (val & mask):
            # print name,bin(val)
            res.append(name)
    return res


def isRelation(flag, name):
    res = getRelation(flag)
    if name in res:
        return True
    else:
        return False


def test_relation():
    print getRelation(SF | OF)
    # print getRelation(CF | getFlag("sf")|  getFlag("of"))
    print isRelation(518, SGE_RELATION)
    print getRelation(ZF | SF | OF)
    print isRelation(ZF | SF | OF, UGE_RELATION)


def main():
    print "Use mask with flag, if maskedflag is target, then it suit the relation"
    print "mask\ttarget\tname"
    for (need, val, name) in listReFlag:
        mask = getMask(need)
        print "{%s\t,%s\t,%s}," % ((mask), (mask & val), name)
        # print "{%s,%s,%s}," %(bin(mask), bin(mask & val) , name)

    test_relation()


if __name__ == '__main__':
    main()
