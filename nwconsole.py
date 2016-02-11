#!/usr/bin/env python
import re
import struct
from binascii import hexlify
try:
	from collections import OrderedDict
except ImportError:
		from ordereddict import OrderedDict
		# OrderedDict=dict
from hashlib import sha256
class NwMessage(object):
	MAGIC_BYTES="\xa9\x00\x01\x00"
	# MAGIC_BYTES="\xa9\x00\x01"
	def __init__(self):
		self.data=NwKeyValue()
		self.protocolVersion=98
		self.messageIdStream=None
		self.messageIdStreamSeek=33
		self.connectionHandle=None

	def fromstring(self,stream):
		assert stream[0:3]==self.MAGIC_BYTES[0:3],\
			"Expected magic bytes, got: {0}".format(hexlify(stream[0:4]))
		self.msglen=struct.unpack("<L",stream[4:8])[0]
		# print "msglen: " + str(self.msglen)
		self.protocolVersion=struct.unpack("<L",stream[8:12])[0]
		assert self.protocolVersion==98,\
		"I only speak protocol version 98, but you gave me {0}".format(self.protocolVersion)
		# lastindex=stream.rfind()
		self.connectionHandle=struct.unpack("<L",stream[21:25])[0]
		self.messageIdStream=stream[12:self.messageIdStreamSeek]
		# print hexlify(self.messageIdStream)
		self.data.fromstring(stream[self.messageIdStreamSeek:])

	def tostring(self):
		out=""+self.MAGIC_BYTES
		kvstream=self.data.tostring()
		# print len(kvstream)
		# print len(kvstream)+8+len(self.messageIdStream)
		out+=struct.pack("<L",len(kvstream)+4+len(self.messageIdStream))
		out+=struct.pack("<L",self.protocolVersion)
		out+=self.messageIdStream[0:9]
		out+=struct.pack("<L",self.connectionHandle)
		out+=self.messageIdStream[13:]
		out+=kvstream
		return out




class NwKeyValue(object):
	def __init__(self):
		self.data=OrderedDict()
	def __getitem__(self,attr):
		return self.data[attr]
	def __setitem__(self,key,item):
		self.data[key]=item

	@classmethod
	def _unpackkv(klass,stream):
		i=0
		keylength=struct.unpack("<L",stream[i:i+4])[0]
		# print "KL: {}".format(keylength)
		i+=4
		key=stream[i:i+keylength]
		# print "KEY: '{}'".format(key)
		i+=keylength
		vallength=struct.unpack("<L",stream[i:i+4])[0]
		# print "VL {}".format(vallength)
		i+=4
		val=stream[i:i+vallength]
		# print "VAL {}".format(val)
		i+=vallength
		return(key,val,i)
		# self.data[key]=val

	def fromstring(self,stream):
		# it is important that the stream starts with message length market	
		# or else it'll get confused
		# seems that in messages it starts at 32 byte mark
		i=0
		while i<len(stream)-1:
			keylength=struct.unpack("<L",stream[i:i+4])[0]
			# print "KL: {}".format(keylength)
			i+=4
			key=stream[i:i+keylength]
			# print "KEY: '{}'".format(key)
			i+=keylength
			vallength=struct.unpack("<L",stream[i:i+4])[0]
			# print "VL {}".format(vallength)
			i+=4
			val=stream[i:i+vallength]
			# print "VAL {}".format(val)
			i+=vallength
			self.data[key]=val
			# print "{} {} {}".format(i,key,val)

	def tostring(self):
		out=""
		for k,v in self.data.items():
			out+=struct.pack("<L",len(k))
			out+=k
			out+=struct.pack("<L",len(v))
			out+=v
		return out






class OpeningMessage(NwMessage):
	def __init__(self):
		super(OpeningMessage,self).__init__()
		self.messageIdStreamSeek=33

class HelloMessage(NwMessage):
	def __init__(self):
		super(HelloMessage,self).__init__()
		self.messageIdStreamSeek=41
		self.messageIdStream="\x01\x00\x03\x00\x00\x01\x00\x00\x00\xdf\x0f\x00\x002\x00\x00\x00hello\x00\x00\x00\x02\x00\x00\x00"
	def tostring(self):
		kwlen=struct.pack("<L",12+len(self.data.tostring()))
		self.messageIdStream=self.messageIdStream[0:13]+kwlen+self.messageIdStream[17:]
		return super(HelloMessage,self).tostring()


class ChallengeMessage(NwMessage):

	def __init__(self):
		super(ChallengeMessage,self).__init__()
		self.messageIdStreamSeek=33
		self.messageIdStream="\x01\x00\x03@\x00\x01\x00\x00\x00\xdf\x0f\x00\x00\xc1\x00\x00\x00\x04\x00\x00\x00"

class LoginResponse(NwMessage):
	def __init__(self):
		super(LoginResponse,self).__init__()
		self.messageIdStreamSeek=41
		self.messageIdStream="\x01\x00\x03\x00\x00\x01\x00\x00\x00\xdf\x0f\x00\x00q\x00\x00\x00login\x00\x00\x00\x02\x00\x00\x00"	
	
	def makehash(self,password,srvhash,gsalt):
		part1=sha256(sha256(password).hexdigest().upper()+gsalt.decode('base64')).hexdigest().upper()
		return sha256("netwitness"+part1+srvhash).hexdigest().upper()


	def tostring(self):
		kwlen=struct.pack("<L",12+len(self.data.tostring()))
		self.messageIdStream=self.messageIdStream[0:13]+kwlen+self.messageIdStream[17:]
		return super(LoginResponse,self).tostring()


class SidMessage(NwMessage):
	def __init__(self):
		super(SidMessage,self).__init__()
		self.messageIdStreamSeek=33
		self.messageIdStream="\x01\x00\x03\x00\x00\x01\x00\x00\x00\xdf\x0f\x00\x00q\x00\x00\x00login\x00\x00\x00\x02\x00\x00\x00"


class AddChan(NwMessage):
	def __init__(self):
		super(AddChan,self).__init__()
		self.messageIdStreamSeek=41 
		self.messageIdStream="\x01\x00\x03\x00\x00\x02\x00\x00\x00Z$\x82\x00j$\x82\x00\x19\x00\x00\x00addChan\x00\x01\x00\x00\x00"
		# print hexlify(self.messageIdStream)
		# print self.messageIdStream.find("addChan")
		self.sid=None

	def tostring(self):
		# print len(self.messageIdStream)
		packedsid=struct.pack("<L",self.sid)
		kwlen=struct.pack("<L",12+len(self.data.tostring()))
		self.messageIdStream=self.messageIdStream[0:13]+packedsid+\
							kwlen+\
							self.messageIdStream[21:]
		# print "\n\n\nXXX {}\n\n\n\n\n".format(hexlify(self.messageIdStream))
		# print len(self.messageIdStream)
		return super(AddChan,self).tostring()

class TargetPid(NwMessage):

		def __init__(self):
			super(TargetPid,self).__init__()
			self.messageIdStream='\x01\x00\x03@\x00\x02\x00\x00\x00\x9b/#\x00\xab/#\x00%\x00\x00\x00\x02\x00\x00\x00'
			self.messageIdStreamSeek=37


class PacketQuery(NwMessage):

	def __init__(self):
		super(PacketQuery,self).__init__()
		self.messageIdStream='\x01\x00\x03\x00\x00\x04\x00\x00\x00Z$\x82\x00j$\x82\x00t$\x82\x00y\x00\x00\x00s\x00\x00\x00packets\x00\x04\x00\x00\x00'
		self.sid=None
		self.pid=None
		self.target=None

	def tostring(self):
		# print len(self.messageIdStream)
		packedsid=struct.pack("<L",self.sid)
		packedpid=struct.pack("<L",self.pid)
		packedtarget=struct.pack("<L",self.target)
		kwlen=struct.pack("<L",12+len(self.data.tostring()))
		self.messageIdStream=self.messageIdStream[0:13]+packedsid+\
							packedpid+packedtarget+kwlen+\
							self.messageIdStream[29:]
		# print "\n\n\nXXX {}\n\n\n\n\n".format(hexlify(self.messageIdStream))
		# print len(self.messageIdStream)
		return super(PacketQuery,self).tostring()

class ProcessedPacketNotice(NwMessage):

	def __init__(self):
		super(ProcessedPacketNotice,self).__init__()
		self.messageIdStream='\x01\x00\x03\x00\x00\x04\x00\x00\x00Z$\x82\x00j$\x82\x00t$\x82\x00y\x00\x00\x00s\x00\x00\x00packets\x00\x02\x00\x00\x00'
		self.sid=None
		self.pid=None
		self.target=None

	def tostring(self):
		# print len(self.messageIdStream)
		packedsid=struct.pack("<L",self.sid)
		packedpid=struct.pack("<L",self.pid)
		packedtarget=struct.pack("<L",self.target)
		kwlen=struct.pack("<L",12+len(self.data.tostring()))
		self.messageIdStream=self.messageIdStream[0:13]+packedsid+\
							packedpid+packedtarget+kwlen+\
							self.messageIdStream[29:]
		# print "\n\n\nXXX {}\n\n\n\n\n".format(hexlify(self.messageIdStream))
		# print len(self.messageIdStream)
		return super(ProcessedPacketNotice,self).tostring()		


# class PacketData(NwMessage):
# 	def __init__(self):
# 		super(PacketData,self).__init__()
# 		self.messageIdStream='\x01\x00\xd1\x01\x01\x00b\x00\x00\x00\x02\x00\x01@\x00\x04\x00\x00\x00Z$\x82\x00j$\x82\x00t$\x82\x00y\x00\x00\x00\xb0\x01\x01\x00\x02\x00\x00\x00'
	
# 	def fromstring(self,stream):
# 		assert stream[0:4]==self.MAGIC_BYTES,\
# 			"Expected magic bytes, got: {}".format(hexlify(stream[0:4]))
# 		self.msglen=struct.unpack("<L",stream[4:8])[0]
# 		# print "msglen: " + str(self.msglen)
# 		self.protocolVersion=struct.unpack("<L",stream[8:12])[0]
# 		assert self.protocolVersion==98,\
# 		"I only speak protocol version 98, but you gave me {}".format(self.protocolVersion)
# 		# lastindex=stream.rfind()
# 		self.connectionHandle=struct.unpack("<L",stream[21:25])[0]
# 		self.messageIdStream=stream[12:self.messageIdStreamSeek]
# 		# print hexlify(self.messageIdStream)
# 		self.data.fromstring(stream[self.messageIdStreamSeek:])		



