# -*- coding: UTF-8 -*-
import socket
from setting import *
from generator import *


class Sender():
    pass


class TCPSender():
     pass
    
    
'''
a sender to send udp packat
'''


class UDPSender():
    def __init__(self, set=None):
        if set is None:
            set = Setting.getDefault()

        self.set = set

        self.data = set.data
        self.host = set.dest_ip
        self.port = set.dest_port
        self.mode = set.mode
        self.interval = set.interval

        self.gen = Generator(set.data)

    def start(self):
        if self.mode == Mode.MANUAL:
            self.send()
        else:
            while (1):
                self.send()
                time.sleep(self.set.interval())

    def send(self):
        # use socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # get data from generator
        msg = self.gen.next()

        # print info in format
        print "UDP:sendto:%s:%s" % (self.host, self.port)
        print "plain:%s" % (msg)
        print "hex:%s"  %( " ".join(["%02x" % ord(c) for c in msg]))
        
        # udp with sendto
        s.sendto(msg, (self.host, self.port))


if __name__ == "__main__":
    set = Setting()
    udp = UDPSender(set)
    udp.start()
