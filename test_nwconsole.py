#!/usr/bin/env python
import re
import unittest
import struct
from binascii import hexlify
from collections import OrderedDict
from hashlib import sha256

from nwconsole import *


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


if __name__=="__main__":
    unittest.main()        