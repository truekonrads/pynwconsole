#!/usr/bin/env python

import nwconsole
import socket
import sys
from  binascii import hexlify
import re
import struct
import time
from optparse import OptionParser
parser=OptionParser()
parser.add_option("-f","--from",
                    dest="from_time",
                    help="time from which to retrieve data in YYYY-MM-DD HH:MM:SS format",
                    # required=True
                    )
parser.add_option("-t","--to",
                    dest="to_time",
                    help="time to which to retrieve data in YYYY-MM-DD HH:MM:SS format"
                    )

parser.add_option("-u","--username",
                    dest="username",                    
                    )

parser.add_option("-p","--password",
                    dest="password",                    
                    )

parser.add_option("-s","--server",
                    dest="hostport",
                    help="Hostname to connect in host:port format"                
                    )

parser.add_option("-o","--output",
                    dest="output",
                    help="Output file, '-' for stdout"       
                    )


(options,args) = parser.parse_args()
    
for k in "hostport password username from_time to_time output".split(" "):
    if getattr(options,k,None) is None:
        # print k
        print >>sys.stderr, "Option {0} missing".format(k)
        parser.print_help()
        sys.exit(0)



s=socket.create_connection(options.hostport.split(":"),15)

m1=nwconsole.OpeningMessage()
m1.fromstring(s.recv(1024))
print >>sys.stderr, "Got hello, protocol version {0}".format(m1.data['pversion'])
# print m1.data.data
# print m1.connectionHandle
m2=nwconsole.HelloMessage()
m2.data['username']=options.username
m2.data['version']=m1.data['pversion']
m2.connectionHandle=m1.connectionHandle
s.send(m2.tostring())
m3=nwconsole.ChallengeMessage()
d=s.recv(1024)
m3.fromstring(d)
print >>sys.stderr, "AuthType {0},  challenge {1}".format(m3.data['authType'],m3.data['hash'])
# print m3.data.data
m4=nwconsole.LoginResponse()
m4.connectionHandle=m1.connectionHandle
m4.data['username']=options.username
m4.data['password']=m4.makehash(options.password,m3.data['hash'],m3.data['gsalt'])
s.send(m4.tostring())
m5=nwconsole.SidMessage()
m5.fromstring(s.recv(1024))
# print m5.data.data
print >>sys.stderr,"SID is {0}".format(m5.data['sid'])
print >>sys.stderr,"----Login successful----"
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
print >>sys.stderr,"Target: {0}, Pid: {1}".format(m7.data['target'],m7.data['pid'])

m8=nwconsole.AddChan()
m8.sid=sid
m8.connectionHandle=m1.connectionHandle
m8.data['path']='/sdk'
m8.data['relativeTo']='1'
s.send(m8.tostring())

m9=nwconsole.TargetPid()
m9.fromstring(s.recv(1024))
# print m7.data.data
print >>sys.stderr,"Target: {0}, Pid: {1}".format(m9.data['target'],m9.data['pid'])
pid=int(m9.data['pid'])
target=int(m9.data['target'])
m10=nwconsole.PacketQuery()
m10.sid=sid
m10.pid=pid
m10.target=target
m10.connectionHandle=m1.connectionHandle
m10.data['time1']=options.from_time     #'2016-02-10 11:55:00'
m10.data['time2']=options.to_time       #'2016-02-10 11:55:15'
m10.data['pathname']='/tmp/foobar'
m10.data['op']='start'
x=m10.tostring()
s.send(x)

if options.output=='-':
    out=sys.stdout
else:
    out=file(options.output,"wb")

# time.sleep(1)
lastbuf=""
totaltransfer=0
while True:
    try:
        buf=s.recv(8)
    except socket.timeout:
        break
    if len(buf)==0:
        break
    assert buf[0:3]==nwconsole.NwMessage.MAGIC_BYTES[0:3],\
    "Expected magic bytes, got: {0}".format(hexlify(buf+s.recv(1024)))
    msglen=struct.unpack("<L",buf[4:8])[0]
    while len(buf)<msglen+8:
        buf+=s.recv(msglen-len(buf)+8)
    if buf.find("Invalid operation 'processed'")>-1:
       
        break
    m=re.search("....percent....(\d+)....count....(\d+)",buf)
    x=buf.find(m.group(0))
    # nwk=nwconsole.NwKeyValue()
    (_,percent,i)=nwconsole.NwKeyValue._unpackkv(buf[x:])
    (_,count,i)=nwconsole.NwKeyValue._unpackkv(buf[x+i:])
    if int(count)%100==0:
        pkt=nwconsole.ProcessedPacketNotice()
        pkt.sid=sid
        pkt.pid=pid
        pkt.target=target
        pkt.data['op']='processed'
        pkt.data['count']=count
        pkt.connectionHandle=m1.connectionHandle
        s.send(pkt.tostring())

    seekpos=x+i
    print >>sys.stderr, "Percent {0}, count {1}, msglen {2}".format(percent,count,msglen)
    totaltransfer+=int(msglen)
    out.write(buf[seekpos:])
    lastbuf=buf

print >>sys.stderr,"Last packet received, done!"
print >>sys.stderr,"Total mbytes transferred: {0}".format(totaltransfer/1024/1024)
s.close()


