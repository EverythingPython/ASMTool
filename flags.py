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
I = int(0x00000001 << 4)
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


CF = int(1 << 0)
PF = int(1 << 2)
AF = int(1 << 4)
ZF = int(1 << 6)
SF = int(1 << 7)
OF = int(1 << 11)

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


Relation = [
	"EQ_RELATION",
	"NE_RELATION",
	"SGT_RELATION",
	"SGE_RELATION",
	"SLT_RELATION",
	"SLE_RELATION",
	"UGT_RELATION",
	"UGE_RELATION",
	"ULT_RELATION",
	"ULE_RELATION",
]

mapReFlag = dict()
mapReFlag[ZF] = "EQ_RELATION"
mapReFlag[rZF] = "NE_RELATION"

mapReFlag[rZF] = "SGT_RELATION"
mapReFlag[SF & OF] = "SGE_RELATION"
mapReFlag[rSF & rOF] = "SGE_RELATION"
mapReFlag[SF & rOF] = "SLT_RELATION"
mapReFlag[rSF & OF] = "SLT_RELATION"
mapReFlag[ZF] = "SLE_RELATION"
mapReFlag[SF & rOF] = "SLE_RELATION"
mapReFlag[rSF & OF] = "SLE_RELATION"

mapReFlag[rCF & rZF] = "UGT_RELATION"
mapReFlag[rCF] = "UGE_RELATION"
mapReFlag[CF] = "ULT_RELATION"
mapReFlag[CF | ZF] = "ULE_RELATION"

for i in mapReFlag:
	print mapReFlag[i], "=", str(bin(i)), "=", i
	# str(int(str(i),2))


# the relations depend on flags
# both F set by or |
# both rF reset by and &
# rF with F, we can ignore F for rF must include other F
# others just do logically
listReFlag = list()
listReFlag.append((["zf"], ZF, "EQ_RELATION"))
listReFlag.append((["zf"], rZF, "NE_RELATION"))
# rZF OF SF, but rZF include others
listReFlag.append((["zf"], rZF , "SGT_RELATION"))
listReFlag.append((["zf", "sf", "of"], rZF & rSF & rOF, "SGT_RELATION"))
listReFlag.append((["sf", "of"], SF & OF, "SGE_RELATION"))
listReFlag.append((["sf", "of"], rSF & rOF, "SGE_RELATION"))
listReFlag.append((["sf", "of"], SF & rOF, "SLT_RELATION"))
listReFlag.append((["sf", "of"], rSF & OF, "SLT_RELATION"))
listReFlag.append((["zf"], ZF, "SLE_RELATION"))
listReFlag.append((["sf", "of"], SF & rOF, "SLE_RELATION"))
listReFlag.append((["sf", "of"], rSF & OF, "SLE_RELATION"))
listReFlag.append((["cf", "zf"], rCF & rZF, "UGT_RELATION"))
listReFlag.append((["cf"], rCF, "UGE_RELATION"))
listReFlag.append((["cf"], CF, "ULT_RELATION"))
listReFlag.append((["cf", "zf"], CF | ZF, "ULE_RELATION"))


for (need, val, name) in listReFlag:
	# print item
	print need, name, "=", bin(val)


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


def doTest():
	print getRelation(SF | OF)
	# print getRelation(CF | getFlag("sf")|  getFlag("of"))
	print isRelation(518, "SGE_RELATION")
	print getRelation(ZF | SF | OF)
	print isRelation(ZF | SF | OF, "UGE_RELATION")


def main():
	doTest()

		print "Use mask with flag, if maskedflag is target, then it suit the relation"
		print "mask\ttarget\tname"
		for (need, val, name) in listReFlag:
			mask = getMask(need)
			print "{%s\t,%s\t,%s}," % ((mask), (mask & val), name)
			# print "{%s,%s,%s}," %(bin(mask), bin(mask & val) , name)


if __name__ == '__main__':
	main()
