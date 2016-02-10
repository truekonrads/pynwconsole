#!/usr/bin/env python
import re
import unittest
import struct
from binascii import hexlify
from collections import OrderedDict
from hashlib import sha256
class NwMessage(object):
	MAGIC_BYTES="\xa9\x00\x01\x00"
	def __init__(self):
		self.data=NwKeyValue()
		self.protocolVersion=98
		self.messageIdStream=None
		self.messageIdStreamSeek=33
		self.connectionHandle=None

	def fromstring(self,stream):
		assert stream[0:4]==self.MAGIC_BYTES,\
			"Expected magic bytes, got: {}".format(hexlify(stream[0:4]))
		self.msglen=struct.unpack("<L",stream[4:8])[0]
		# print "msglen: " + str(self.msglen)
		self.protocolVersion=struct.unpack("<L",stream[8:12])[0]
		assert self.protocolVersion==98,\
		"I only speak protocol version 98, but you gave me {}".format(self.protocolVersion)
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




class TestNwKeyValue(unittest.TestCase):

	test_vector2="\x08\x00\x00\x00authType\n\x00\x00\x00netwitness\x05\x00\x00\x00field\x11\x00\x00\x00username,password\x04\x00\x00\x00hash@\x00\x00\x00245DAC0E6E16F172516F6542759562FA68130EE9B0852BE2F401961FCE7AB3CD\x05\x00\x00\x00gsalt,\x00\x00\x006Z1RUlhEPfDK6Cx8Pvd0VdWmHCGQFVM+dHvJ7VwZbs8="
	test_result2={
	'authType':'netwitness',
	'field': 'username,password',
	'hash': '245DAC0E6E16F172516F6542759562FA68130EE9B0852BE2F401961FCE7AB3CD',
	'gsalt': '6Z1RUlhEPfDK6Cx8Pvd0VdWmHCGQFVM+dHvJ7VwZbs8='
	}

	test_vector="\x06\x00\x00\x00handle\x07\x00\x00\x002305947\x08\x00\x00\x00pversion\x02\x00\x00\x0098\x07\x00\x00\x00trusted\x01\x00\x00\x000"
	test_result={
	'handle':'2305947',
	'pversion':"98",
	'trusted':'0'
	}

	test_vector3="\xa9\x00\x01\x00P\x00\x00\x00b\x00\x00\x00\x01\x00\x03@\x00\x01\x00\x00\x00\x9b/#\x00;\x00\x00\x00\x03\x00\x00\x00\x06\x00\x00\x00handle\x07\x00\x00\x002305947\x08\x00\x00\x00pversion\x02\x00\x00\x0098\x07\x00\x00\x00trusted\x01\x00\x00\x000"

	def test_from_string_parser(self):
		x=NwKeyValue()
		x.fromstring(self.test_vector)
		self.assertEquals(self.test_result,x.data)


	def test_from_string_parser2(self):
		
		x=NwKeyValue()
		x.fromstring(self.test_vector2)
		self.assertEquals(self.test_result2,x.data)

	def test_to_string(self):
		x=NwKeyValue()
		x.fromstring(self.test_vector2)		
		self.assertEquals(x.tostring(),self.test_vector2)


	def test_parse_message(self):
		nm=NwMessage()
		nm.fromstring(self.test_vector3)
		self.assertEquals(nm.data.data,self.test_result)

	def test_message_to_string(self):
		nm=NwMessage()
		nm.fromstring(self.test_vector3)
		out=nm.tostring()
		self.assertEquals(out,self.test_vector3)

class OpeningMessage(NwMessage):
	def __init__(self):
		super(OpeningMessage,self).__init__()
		self.messageIdStreamSeek=33

class HelloMessage(NwMessage):
	def __init__(self):
		super(HelloMessage,self).__init__()
		self.messageIdStreamSeek=41
		self.messageIdStream="\x01\x00\x03\x00\x00\x01\x00\x00\x00\xdf\x0f\x00\x002\x00\x00\x00hello\x00\x00\x00\x02\x00\x00\x00"


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



# class ChanReply(NwMessage):


	# def fromsting(self,stream):
	# 	raise NotImplemenetdError,\
	# 		"the NwKeyValue is broken here a little"


	# def tostring(self):












if __name__=="__main__":
	unittest.main()