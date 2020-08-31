# -*- coding: UTF-8 -*-
import sys
import struct
from setting import *


class Generator():
    def __init__(self, data=[]):
        self.data = data

    def next(self):
        num = len(self.data)
        for i in range(num):
            field = self.data[i]
            (type, change, value) = field
            if type == 'i':
                if change == Sym.INC:
                    value += 1
                elif change == Sym.DEC:
                    value -= 1
            field = (type, change, value)
            self.data[i] = field

        # use netword byte order
        mode = "!"
        item = []
        output = ""
        for field in self.data:
            (type, change, value) = field
            output += str(value)
            mode += type
            item.append(value)

        output = struct.pack(mode, *item)
        '''
        print mode
        print item
        print output
        '''
        print "next msg items:%s" % item
        return output


if __name__ == "__main__":
    data = [
        ('3s', None, "test"),
        ('i', Sym.INC, 1),
        ('i', None, 1),
    ]
    g = Generator()
    g.data = data
    print g.next()
    print g.next()
    print g.next()
