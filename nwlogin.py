#!/usr/bin/env python

import nwconsole
import socket
import sys
import binascii
s=socket.create_connection((sys.argv[1],sys.argv[2]))

m1=nwconsole.OpeningMessage()
m1.fromstring(s.recv(1024))
# print m1.data.data
# print m1.connectionHandle
m2=nwconsole.HelloMessage()
m2.data['username']=sys.argv[3]
m2.data['version']='92'
m2.connectionHandle=m1.connectionHandle
s.send(m2.tostring())
m3=nwconsole.ChallengeMessage()
m3.fromstring(s.recv(1024))
# print m3.data.data
m4=nwconsole.LoginResponse()
m4.connectionHandle=m1.connectionHandle
m4.data['username']=sys.argv[3]
m4.data['password']=m4.makehash(sys.argv[4],m3.data['hash'],m3.data['gsalt'])
s.send(m4.tostring())
print "----Login----"
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
# print binascii.hexlify(x)
# print "Handle is {}".format(m1.connectionHandle)
s.send(x)
m7=nwconsole.TargetPid()
m7.fromstring(s.recv(1024))
# print m7.data.data
print "Target: {}, Pid: {}".format(m7.data['target'],m7.data['pid'])

m8=nwconsole.AddChan()
m8.sid=sid
m8.connectionHandle=m1.connectionHandle
m8.data['path']='/sdk'
m8.data['relativeTo']='1'
s.send(m8.tostring())

m9=nwconsole.TargetPid()
m9.fromstring(s.recv(1024))
# print m7.data.data
print "Target: {}, Pid: {}".format(m9.data['target'],m9.data['pid'])
pid=int(m9.data['pid'])
target=int(m9.data['target'])
m10=nwconsole.PacketQuery()
m10.sid=sid
m10.pid=pid
m10.target=target
m10.connectionHandle=m1.connectionHandle
m10.data['time1']='2016-02-10 11:55:00'
m10.data['time2']='2016-02-10 11:55:15'
m10.data['pathname']='/tmp/foobar'
m10.data['op']='start'
x=m10.tostring()
s.send(x)
print s.recv(1024)
s.close()



