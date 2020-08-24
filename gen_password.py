
import random



def gen_pass(candidate, size):
    res = []
    n = len(candidate)
    for _ in range(size):
        idx = random.randint(0,n-1)
        res.append(chr(candidate[idx]))
    return ''.join(res)


candidate =[]
for i in range(ord('a'),ord('z')):
    candidate.append(i)
for i in range(ord('0'),ord('9')):
    candidate.append(i)
    
res = gen_pass(candidate,32)
print(res)
