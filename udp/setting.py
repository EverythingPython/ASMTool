# -*- coding: UTF-8 -*-
import sys, json, time

'''
Format	C Type	Python	字节数
x	pad byte	no value	1
c	char	string of length 1	1
b	signed char	integer	1
B	unsigned char	integer	1
?	_Bool	bool	1
h	short	integer	2
H	unsigned short	integer	2
i	int	integer	4
I	unsigned int	integer or long	4
l	long	integer	4
L	unsigned long	long	4
q	long long	long	8
Q	unsigned long long	long	8
f	float	float	4
d	double	float	8
s	char[]	string	1
p	char[]	string	1
P	void *	long
'''

class Sym():
    INC = "inc"
    DEC = "dec"


class Mode():
    MANUAL = "manual"
    AUTO = "auto"

class Setting():
    # we have set a default configuration here
    userdef = {
        "mode": "manual",
        "dest_ip": "192.168.1.1",
        "dest_port": 3333,
        "data": [
            ('i', "inc", 1),
            ('i', "dec", 1),
            ('s', "", "1"),
        ]
    }

    @staticmethod
    def getDefault():
        set = Setting()
        return set

    def __getattr__(self, name):
        if self._rData.has_key(name):
            default = self._rData[name]["default"]
            return self.config.get(name, default)
        else:
            return None

    def __init__(self):
        self._rData = {
            "mode": {"default": Mode.MANUAL},
            "dest_ip": {"default": "127.0.0.1"},
            "dest_port": {"default": 80},
            "data": {"default": []},
            "interval": {"default": "2"},
            "test": {"default": "test"},
        }
        self.read_config()

    @classmethod
    def get_val(cls, key):
        val = cls.config[key]
        return val

    @classmethod
    def set_val(cls, key, val):
        cls.config[key] = val

    @classmethod
    def read_config(cls):
        '''
        file = open("config")
        mystr=""
        while 1:
            line = file.readline()
            if line=="":
                break
            mystr+=line
        print mystr
        print eval(mystr)
        myjson = json.loads(mystr)
        print myjson
        cls.config=myjson
        '''
        cls.config = cls.userdef
        print cls.config


if __name__ == "__main__":
    set = Setting()
    print set.config
