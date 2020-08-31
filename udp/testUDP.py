from setting import  *
from sender import  *
from generator import *


if __name__=="__main__":
    userdef ={
        "mode":"manual",
        "dest_ip": "192.168.1.1",
        "dest_port": 3333,
        "data": [
            ('i', "inc", 1),
            ('i', "dec", 1),
            ('3s', "", "1"),
         ]
    }

    Setting.userdef=userdef
    udp = UDPSender()
    udp.start()