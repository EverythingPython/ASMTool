# int v5 = v0.length;
#                 byte[] v1 = new byte[]{78, 101, 116, 101, 97, 115, 101};
#                 int v2 = 0;
#                 int v3 = 0;
#                 while (v2 < v5) {
#                     if (v3 >= 7) {
#                         v3 = 0;
#                     }
#                     v0[v2] = ((byte) (v0[v2] ^ v1[v3]));
#                     v2++;
#                     v3++;
#                 }

import base64

def decode(s):
    res = []
    n = len(s)
    i, j =0,0
    key = 'netease'
    while i<n:
        if j>=7:
            j=0
        res .append( ord(s[i]) ^ ord(key[j]   ))
        i+=1

    print(res)
    print(''.join([chr(i) for i in res]))

# md5
byte  = base64.b64decode('AyFB')
decode(byte.decode())

# jinli
byte  = base64.b64decode('IRUECg')
decode(byte.decode())