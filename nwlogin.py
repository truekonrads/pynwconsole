#!/usr/bin/env python

import nwconsole
import socket
import sys
s=socket.create_connection((sys.argv[1],sys.argv[2]))

m1=nwconsole.OpeningMessage()
m1.fromstring(s.recv(1024))
print m1.data.data
print m1.connectionHandle
m2=nwconsole.HelloMessage()
m2.data['username']='admin'
m2.data['version']='92'
m2.connectionHandle=m1.connectionHandle
s.send(m2.tostring())
m3=nwconsole.ChallengeMessage()
m3.fromstring(s.recv(1024))
print m3.data.data
m4=nwconsole.LoginResponse()
m4.connectionHandle=m1.connectionHandle
m4.data['username']='admin'
m4.data['password']=m4.makehash('netwitness',m3.data['hash'],m3.data['gsalt'])
s.send(m4.tostring())
print "----"
print s.recv(1024)
s.close()



