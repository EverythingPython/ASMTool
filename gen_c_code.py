
import sys,os
import sh
import pystache

code = u'''
#include <stdio.h>

int main(){
 for (int i=0;i<20;i++){
    {{&code}}
 }
    return 0;
}

'''

s=u'''
printf("hello");
'''

data = {'code':s}

render = pystache.Renderer()
parsed = pystache.parse(code)
res = render.render(parsed, data,)
print(res)
with open('test.c','w') as fp:
    fp.write(res)

# gcc=sh.Command('gcc')
# gcc("-g -o test.out test.c".split(' '))
