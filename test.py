
target = '0a'
for t in range(4):
    for i in range(256):
        res = i
        for _ in range(t):
            res = (res<<6) | i

        for bit in [8,16,24,10,2]:
            if hex(res>>bit).endswith(target):
                print(t,i, res, hex(res),hex(res>>bit))

    