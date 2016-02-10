#!/usr/bin/env python

import nwconsole
import socket
import sys
import binascii
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
m5=nwconsole.SidMessage()
m5.fromstring(s.recv(1024))
# print m5.data.data
print "SID is {}".format(m5.data['sid'])
sid=int(m5.data['sid'])
m6=nwconsole.AddChan()
m6.sid=sid
m6.connectionHandle=m1.connectionHandle
m6.data['path']='/'
x=m6.tostring()
# print len(x)
# print x
print binascii.hexlify(x)
# print "Handle is {}".format(m1.connectionHandle)
s.send(x)
print s.recv(1024)
s.close()



