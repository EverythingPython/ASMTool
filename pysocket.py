#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
socket server
'''
import socket
import sh
import re

def local_ip():
    res = sh.ifconfig().stdout
    ip = None
    m = re.search(r'inet (30[0-9\.]+[0-9]+)', res)
    if m:
        print(m.group(1))
        ip = m.group(1)
    return ip  

ip = local_ip()
print(ip)
ip_port = (ip,9990)

sk = socket.socket()

sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR , 1)
sk.bind(ip_port)
sk.listen(5)

try:
    while True:
        print 'server waiting...'
        conn,addr = sk.accept()
        print(conn,addr)

        '''
        TODO: write your IO logic here
        '''

        conn.send('1234')
        conn.send('1234')
        #client_data = conn.recv(1024)
        #print client_data
        
        # conn.sendall('不要回答,不要回答,不要回答')

        conn.close()
except:
    if conn:
        conn.close()
    sk.close()
