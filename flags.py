import sys
import os

from collections import defaultdict, namedtuple
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

Condition = namedtuple('Condition', ['mask', 'target', 'flag'])


class RelationNode(object):
    mapping = {}

    def __init__(self, name, jcc=None):
        self.name = name
        if jcc:
            self.jcc = jcc
        else:
            self.jcc = set()

        self.children = []
        self.conds = []

        # update info
        self.generate_jcc()

        # update class attr
        self.mapping[name] = self

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    @staticmethod
    def get_mask(need):
        # get the flag we need as mask
        mask = 0
        for i in need:
            mask = mask | flagDict[i]
        return mask

    def generate_jcc(self):
        # set the jcc info, never add negative e.g. jna
        name = self.name
        jcc = self.jcc

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
                temp.add(i + 'e')
            jcc.add('je')
            jcc.update(temp)

        logging.debug(jcc)

    def feat(self, flag_value):
        # Use mask with flag, if maskedflag is target, then it suit the relation
        for cond in self.conds:
            # mask flag and value
            # if they are same , them it is
            if (cond.mask & flag_value) == cond.target:
                return True
        return False

    def add_jcc(self, *args):
        self.jcc.update(args)

    def add_child(self, *child):
        self.children += child

    def add_cond(self, flag, value):
        mask = self.get_mask(flag)
        target = mask & value
        self.conds.append(Condition(mask, target, flag))
        logging.debug("{}\t, {}\t, {}".format(mask, target, self.name))


# Relations
EQ_RELATION = RelationNode("EQ_RELATION")
NE_RELATION = RelationNode("NE_RELATION")
SGT_RELATION = RelationNode("SGT_RELATION")
SGE_RELATION = RelationNode("SGE_RELATION")
SLT_RELATION = RelationNode("SLT_RELATION")
SLE_RELATION = RelationNode("SLE_RELATION")
UGT_RELATION = RelationNode("UGT_RELATION")
UGE_RELATION = RelationNode("UGE_RELATION")
ULT_RELATION = RelationNode("ULT_RELATION")
ULE_RELATION = RelationNode("ULE_RELATION")

# Dependency using children
# = then must >= <= and so on
EQ_RELATION.add_child(SGE_RELATION, SLE_RELATION,
                      UGE_RELATION, ULE_RELATION)
# != may no child
NE_RELATION
# > then must >=, vice versa
SGT_RELATION.add_child(SGE_RELATION)
SLT_RELATION.add_child(SLE_RELATION)
UGT_RELATION.add_child(UGE_RELATION)
ULT_RELATION.add_child(ULE_RELATION)

# the relations depend on flags
# both F set by or |
# both rF reset by and &
# rF with F, we can ignore F for rF must include other F
# others just do logically
# we may lost some of them which can get by Dependency
EQ_RELATION.add_cond(["zf"], ZF, )

NE_RELATION.add_cond(["zf"], rZF, )

# rZF OF SF, but rZF include others
SGT_RELATION.add_cond(["zf"], rZF, )
SGT_RELATION.add_cond(["zf", "sf", "of"], rZF & rSF & rOF, )

SGE_RELATION.add_cond(["sf", "of"], SF & OF, )
SGE_RELATION.add_cond(["sf", "of"], rSF & rOF, )

SLT_RELATION.add_cond(["sf", "of"], SF & rOF, )
SLT_RELATION.add_cond(["sf", "of"], rSF & OF, )

SLE_RELATION.add_cond(["zf"], ZF, )
SLE_RELATION.add_cond(["sf", "of"], SF & rOF, )
SLE_RELATION.add_cond(["sf", "of"], rSF & OF, )

UGT_RELATION.add_cond(["cf", "zf"], rCF & rZF, )

UGE_RELATION.add_cond(["cf"], rCF, )

ULT_RELATION.add_cond(["cf"], CF, )

ULE_RELATION.add_cond(["cf"], CF, )
ULE_RELATION.add_cond(['zf'], ZF, )


class FlagCheck():
    def __init__(self):
        self.flags = []

    def get_feasible(self, flag_value):
        res = set()

        for relation in RelationNode.mapping.itervalues():
            if relation.feat(flag_value):
                res.add(relation)
        children = [r.children for r in res]
        for c in children:
            res.update(c)

        return res

    def getJcc(self, flag_value):
        # get the target flag first, and check if it suits
        feasible = self.get_feasible(flag_value)
        res = set()
        for r in feasible:
            res.update(r.jcc)

        logging.debug('flag {} = {} may mean:{}'.format(flag_value, bin(flag_value), res))
        return res

    def getRelation(self, flag_value):
        # get the target flag first, and check if it suits
        feasible = self.get_feasible(flag_value)
        res = [r.name for r in feasible]
        logging.debug('flag {} = {} may mean:{}'.format(flag_value, bin(flag_value), res))
        return res

    def isRelation(self, flag, relation):
        feasible = self.get_feasible(flag)
        res = False

        if relation in feasible:
            res = True
            logging.debug('flag {} = {} match:{}'.format(flag, bin(flag), relation))
        return res


def test_relation():
    checker = FlagCheck()
    print('Test report as bellow:')
    print(checker.getRelation(SF | OF))
    # print getRelation(CF | getFlag("sf")|  getFlag("of"))
    print(checker.isRelation(518, SGE_RELATION))
    print(checker.getRelation(ZF | SF | OF))
    print(checker.isRelation(ZF | SF | OF, UGE_RELATION))


def main():
    test_relation()


if __name__ == '__main__':
    main()
