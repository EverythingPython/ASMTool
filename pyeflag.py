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

# bit offset of each flag
eflags = {
    'SF': 7,
    'ZF': 6,
    'CF': 0,
    'OF': 11,
    'DF': 10,
    'PF': 2,
    'AF': 4
}

# 32...0
flagDict = dict()

for flag in eflags:
    offset = eflags[flag]

    # target flag set
    bit = int(1 << offset)
    flip = 65535 - bit

    flagDict[flag] = bit
    # logging.debug(i, "=", bin(flagDict[i]), " and reverse=", r, "=", bin(r))

    # both F_1 means flag set
    # both F_0 means flag reset

    # WARNING: positive flag init as 0xff..ff, just a representation
    globals()['{}_1'.format(flag)] = 65535 | bit
    # CF = 65535 | int(1 << 0)
    # PF = 65535 | int(1 << 2)
    # AF = 65535 | int(1 << 4)
    # ZF = 65535 | int(1 << 6)
    # SF = 65535 | int(1 << 7)
    # OF = 65535 | int(1 << 11)

    # target flag reset no matter what others
    globals()['{}_0'.format(flag)] = 65535 ^ bit
    # rCF = 65535 ^ int(1 << 0)
    # rPF = 65535 ^ int(1 << 2)
    # rAF = 65535 ^ int(1 << 4)
    # rZF = 65535 ^ int(1 << 6)
    # rSF = 65535 ^ int(1 << 7)
    # rOF = 65535 ^ int(1 << 11)

Condition = namedtuple('Condition', ['mask', 'target', 'flag'])


class RelationNode(object):
    mapping = {}

    def __init__(self, name, jcc=None):
        self.name = name
        if jcc:
            self.jcc = jcc
        else:
            self.jcc = set()
        self.no_jcc = set()
        self.children = []
        self.conditions = []

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
            flag = i.split('_')[0]
            mask = mask | flagDict[flag]
        return mask

    @staticmethod
    def get_value(need):
        value = 65535
        for flag in need:
            value = globals()[flag] & value
        return value

    def generate_jcc(self):
        # set the jcc info, never add negative e.g. jna
        name = self.name
        jcc = self.jcc

        # get from name, get others from dependency
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

        if 'jne' in jcc:
            # some of them should be removed
            self.no_jcc.update(['je'])

        logging.debug('relation {} means {}'.format(self.name, str(jcc)))

    def feat(self, flag_value):
        # Use mask with flag, if maskedflag is target, then it suit the relation
        for cond in self.conditions:
            # mask flag and value
            # if they are same , them it is
            if (cond.mask & flag_value) == cond.target:
                return True
        return False

    def add_jcc(self, *args):
        self.jcc.update(args)

    def add_child(self, *child):
        self.children += child

    def add_cond(self, flag):

        mask = self.get_mask(flag)
        value = self.get_value(flag)

        target = mask & value
        self.conditions.append(Condition(mask, target, flag))
        logging.debug("{}\t, {}\t, {}".format(mask, target, self.name))


class FlagCheck():
    def __init__(self):
        self.flags = []

    def get_feasible(self, flag_value):
        res = set()
        for relation in RelationNode.mapping.values():
            if relation.feat(flag_value):
                res.add(relation)

        children = [r.children for r in res]
        for c in children:
            res.update(c)

        return res

    def get_jcc(self, flag_value):
        # get the target flag first, and check if it suits
        feasible = self.get_feasible(flag_value)
        res = set()
        for r in feasible:
            res.update(r.jcc)

        # special case: for jne, must no je
        if 'jne' in res:
            res.remove('je')

        logging.debug('flag {} = {} may mean:{}'.format(flag_value, bin(flag_value), res))
        return res

    def get_relation(self, flag_value):
        # get the target flag first, and check if it suits
        feasible = self.get_feasible(flag_value)
        res = [r.name for r in feasible]
        logging.debug('flag {} = {} may mean:{}'.format(flag_value, bin(flag_value), res))
        return res

    def is_relation(self, flag, relation):
        feasible = self.get_feasible(flag)
        res = False

        if relation in feasible:
            res = True
            logging.debug('flag {} = {} match:{}'.format(flag, bin(flag), relation))
        return res


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
# the list of the flag_? means the relation requires the flag value
# we may lost some of them here which can get by Dependency later
EQ_RELATION.add_cond(["ZF_1"])

NE_RELATION.add_cond(["ZF_0"])

# ZF_0 OF_1 SF_1, but ZF_0 include others
SGT_RELATION.add_cond(["ZF_0", ])
SGT_RELATION.add_cond(["ZF_0", "SF_0", "OF_0", ])

# sf ^ of == 0
SGE_RELATION.add_cond(["SF_1", "OF_1", ])
SGE_RELATION.add_cond(["SF_0", "OF_0", ])

# sf ^ of ==1
SLT_RELATION.add_cond(["SF_1", "OF_0", ])
SLT_RELATION.add_cond(["SF_0", "OF_1", ])

# zf || sf ^ of ==1
SLE_RELATION.add_cond(["ZF_1", ])
SLE_RELATION.add_cond(["SF_1", "OF_0", ])
SLE_RELATION.add_cond(["SF_0", "OF_1", ])

# !cf && !zf
UGT_RELATION.add_cond(["CF_0", "ZF_0", ])

UGE_RELATION.add_cond(["CF_0", ])

ULT_RELATION.add_cond(["CF_1", ])

ULE_RELATION.add_cond(["CF_1", ])
ULE_RELATION.add_cond(["ZF_1", ])


def test_relation():
    checker = FlagCheck()
    print('Test report as bellow:')
    print(checker.get_relation(RelationNode.get_value(["SF_1", "OF_1"])))
    # print getRelation(CF_1 | getFlag("sf")|  getFlag("of"))
    print(checker.is_relation(518, SGE_RELATION))
    print(checker.get_relation(RelationNode.get_value(['ZF_1', 'SF_1', 'OF_1'])))
    print(checker.is_relation(RelationNode.get_value(['ZF_1', 'SF_1', 'OF_1']), UGE_RELATION))


def main():
    test_relation()


if __name__ == '__main__':
    main()
