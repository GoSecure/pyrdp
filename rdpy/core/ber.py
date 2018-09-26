#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
Basic Encoding Rules use in RDP.
ASN.1 standard
"""

from rdpy.core.packing import Uint8, Uint16BE
from rdpy.core.error import InvalidExpectedDataException, InvalidSize

class BerPc(object):
    BER_PC_MASK = 0x20
    BER_PRIMITIVE = 0x00
    BER_CONSTRUCT = 0x20

class Class(object):
    BER_CLASS_MASK = 0xC0
    BER_CLASS_UNIV = 0x00
    BER_CLASS_APPL = 0x40
    BER_CLASS_CTXT = 0x80
    BER_CLASS_PRIV = 0xC0
        
class Tag(object):
    BER_TAG_MASK = 0x1F
    BER_TAG_BOOLEAN = 0x01
    BER_TAG_INTEGER = 0x02
    BER_TAG_BIT_STRING = 0x03
    BER_TAG_OCTET_STRING = 0x04
    BER_TAG_OBJECT_IDENFIER = 0x06
    BER_TAG_ENUMERATED = 0x0A
    BER_TAG_SEQUENCE = 0x10
    BER_TAG_SEQUENCE_OF = 0x10

def berPC(pc):
    """
    @summary: Return BER_CONSTRUCT if true, BER_PRIMITIVE if false
    @param pc: boolean
    @return: BerPc value
    """
    if pc:
        return BerPc.BER_CONSTRUCT
    else:
        return BerPc.BER_PRIMITIVE
    
def readLength(s):
    """
    @summary: Read length of BER structure
    Length is on 1, 2 or 3 bytes
    @param s: stream
    @return: int
    """

    byte = Uint8.unpack(s.read(1))
    if byte & 0x80:
        byte &= ~0x80

        if byte == 1:
            return Uint8.unpack(s.read(1))
        elif byte == 2:
            return Uint16BE.unpack(s.read(2))
        else:
            raise InvalidExpectedDataException("BER length must be 1 or 2")
    else:
        return byte

def writeLength(size):
    """
    @summary: Return structure length as expected in BER specification
    @param size: int
    @return: str
    """
    if size > 0x7f:
        return Uint8.pack(0x82) + Uint16BE.pack(size)
    else:
        return Uint8.pack(size)
    
def readUniversalTag(s, tag, pc):
    """
    @summary: Read tag of BER packet
    @param tag: Class attributes
    @param pc: boolean
    @return: true if tag was read correctly
    """
    byte = Uint8.unpack(s.read(1))
    return byte == ((Class.BER_CLASS_UNIV | berPC(pc)) | (Tag.BER_TAG_MASK & tag))

def writeUniversalTag(tag, pc):
    """
    @summary: Return universal tag byte
    @param tag: tag class attributes
    @param pc: boolean
    @return: str
    """
    return Uint8.pack((Class.BER_CLASS_UNIV | berPC(pc)) | (Tag.BER_TAG_MASK & tag))

def readApplicationTag(s, tag):
    """
    @summary: Read application tag
    @param s: stream
    @param tag: tag class attributes
    @return: length of application packet
    """
    byte = Uint8.unpack(s.read(1))
    
    if tag > 30:
        if byte != ((Class.BER_CLASS_APPL | BerPc.BER_CONSTRUCT) | Tag.BER_TAG_MASK):
            raise InvalidExpectedDataException()
        
        byte = Uint8.unpack(s.read(1))
        if byte != tag:
            raise InvalidExpectedDataException("bad tag")
    else:
        if byte != ((Class.BER_CLASS_APPL | BerPc.BER_CONSTRUCT) | (Tag.BER_TAG_MASK & tag)):
            raise InvalidExpectedDataException()
        
    return readLength(s)

def writeApplicationTag(tag, size):
    """
    @summary: Encode a BER application tag
    @param tag: BER tag
    @param size: size of the rest of the packet  
    """
    if tag > 30:
        return Uint8.pack((Class.BER_CLASS_APPL | BerPc.BER_CONSTRUCT) | Tag.BER_TAG_MASK) + Uint8.pack(tag) + writeLength(size)
    else:
        return Uint8.pack((Class.BER_CLASS_APPL | BerPc.BER_CONSTRUCT) | (Tag.BER_TAG_MASK & tag)) + writeLength(size)
    
def readBoolean(s):
    """
    @summary: Decode a BER boolean
    @param s: stream
    @return: boolean
    """
    if not readUniversalTag(s, Tag.BER_TAG_BOOLEAN, False):
        raise InvalidExpectedDataException("Bad boolean tag")

    size = readLength(s)
    if size != 1:
        raise InvalidExpectedDataException("Bad boolean size")
    
    b = Uint8.unpack(s.read(1))
    return bool(b)

def writeBoolean(b):
    """
    @summary: Encode a BER boolean
    @param b: boolean
    @return: str
    """
    boolean = Uint8.pack(0xff if b else 0)
    return writeUniversalTag(Tag.BER_TAG_BOOLEAN, False) + writeLength(1) + boolean

def readInteger(s):
    """
    @summary: Decode a BER integer
    @param s: stream
    @return: int
    """
    if not readUniversalTag(s, Tag.BER_TAG_INTEGER, False):
        raise InvalidExpectedDataException("Bad integer tag")
    
    size = readLength(s)
    
    if size == 1:
        return Uint8.unpack(s.read(1))
    elif size == 2:
        return Uint16BE.unpack(s.read(2))
    elif size == 3:
        integer1 = Uint8.unpack(s.read(1))
        integer2 = Uint16BE.unpack(s.read(2))
        return (integer1 << 16) + integer2
    elif size == 4:
        return Uint32BE.unpack(s.read(4))
    else:
        raise InvalidExpectedDataException("Wrong integer size")
    
def writeInteger(value):
    """
    @summary: Encode a BER integer
    @param param: int
    @return: str
    """
    if value <= 0xff:
        return writeUniversalTag(Tag.BER_TAG_INTEGER, False) + writeLength(1) + Uint8.pack(value)
    elif value <= 0xffff:
        return writeUniversalTag(Tag.BER_TAG_INTEGER, False) + writeLength(2) + Uint16BE.pack(value)
    else:
        return writeUniversalTag(Tag.BER_TAG_INTEGER, False) + writeLength(4) + Uint32BE.pack(value)

def readOctetString(s):
    """
    @summary: Decode a BER octet string
    @param s: stream
    @return: str
    """
    if not readUniversalTag(s, Tag.BER_TAG_OCTET_STRING, False):
        raise InvalidExpectedDataException("Bad octet string tag")
    
    size = readLength(s)
    return s.read(size)

def writeOctetstring(value):
    """
    @summary: Encode a BER octet string
    @param value: str
    @return: str
    """
    return writeUniversalTag(Tag.BER_TAG_OCTET_STRING, False) + writeLength(len(value)) + value

def readEnumerated(s):
    """
    @summary: Decode a BER enumeration value
    @param s: stream
    @return: int or long
    """
    if not readUniversalTag(s, Tag.BER_TAG_ENUMERATED, False):
        raise InvalidExpectedDataException("Bad enumeration tag")
    
    if readLength(s) != 1:
        raise InvalidSize("Enumeration size must be 1")
    
    return Uint8.unpack(s.read(1))

def writeEnumerated(enumerated):
    """
    @summary: Encode a BER enumeration value
    @param s: stream
    @return: str
    """
    return writeUniversalTag(Tag.BER_TAG_ENUMERATED, False) + writeLength(1) + Uint8.pack(enumerated)