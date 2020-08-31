# coding=utf-8
import sys, os
import sh
from pprint import pprint

adb = sh.Command('adb')
res = adb('shell pm list package'.split(' '))
lines = res.stdout.decode().split('\n')
pprint(lines)
apk = [i.split(':')[-1] for i in lines if 'miui' in i]
print(len(apk))
for a in apk:
    res = adb(['shell','pm', 'path', a])
    path = res.stdout.decode().strip().split(':')[-1]

    name = path.split('/')[-1]
    if os.path.isfile('examples/miui/{}'.format(name)):
        print('pulled {}'.format(path))
        continue
    try:
        print('new pull {}'.format(path))
        adb(['pull', path, 'examples/miui/'])
    except:
        pass
