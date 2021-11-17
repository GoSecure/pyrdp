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
Basic Encoding Rules utility functions.
ASN.1 standard.
"""

from enum import IntEnum
from typing import BinaryIO

from pyrdp.core.packing import Uint8, Uint16BE, Uint32BE

class PC(IntEnum):
    BER_PC_MASK = 0x20
    BER_PRIMITIVE = 0x00
    BER_CONSTRUCT = 0x20

class Class(IntEnum):
    BER_CLASS_MASK = 0xC0
    BER_CLASS_UNIV = 0x00
    BER_CLASS_APPL = 0x40
    BER_CLASS_CTXT = 0x80
    BER_CLASS_PRIV = 0xC0
        
class Tag(IntEnum):
    BER_TAG_MASK = 0x1F
    BER_TAG_BOOLEAN = 0x01
    BER_TAG_INTEGER = 0x02
    BER_TAG_BIT_STRING = 0x03
    BER_TAG_OCTET_STRING = 0x04
    BER_TAG_OBJECT_IDENFIER = 0x06
    BER_TAG_ENUMERATED = 0x0A
    BER_TAG_SEQUENCE = 0x10
    BER_TAG_SEQUENCE_OF = 0x10

def berPC(isConstruct: bool) -> PC:
    """
    Return BER_CONSTRUCT if true, BER_PRIMITIVE if false
    :param isConstruct: True if BER_CONSTRUCT expected
    :return: BERPC value
    """
    if isConstruct:
        return PC.BER_CONSTRUCT
    else:
        return PC.BER_PRIMITIVE
    
def readLength(s: BinaryIO) -> int:
    """
    Read length of BER structure
    Length is on 1, 2 or 3 bytes
    :param s: stream
    """

    byte = Uint8.unpack(s.read(1))
    if byte & 0x80:
        byte &= ~0x80

        if byte == 1:
            return Uint8.unpack(s.read(1))
        elif byte == 2:
            return Uint16BE.unpack(s.read(2))
        else:
            raise ValueError("BER length must be 1 or 2")
    else:
        return byte

def writeLength(length: int) -> bytes:
    """
    Pack structure length as expected in BER specification
    :param length: structure length.
    """
    if length > 0x7f:
        return Uint8.pack(0x82) + Uint16BE.pack(length)
    else:
        return Uint8.pack(length)
    
def readUniversalTag(s: BinaryIO, tag: Tag, isConstruct: bool) -> bool:
    """
    Unpack universal tag and return True if the proper tag was read.
    :param s: stream
    :param tag: BER tag
    :param isConstruct: True if a construct is expected
    """
    byte = Uint8.unpack(s.read(1))
    return byte == ((Class.BER_CLASS_UNIV | berPC(isConstruct)) | (Tag.BER_TAG_MASK & tag))

def writeUniversalTag(tag: Tag, isConstruct: bool) -> bytes:
    """
    Pack universal tag.
    :param tag: BER tag
    :param isConstruct: True if the structure is a construct
    """
    return Uint8.pack((Class.BER_CLASS_UNIV | berPC(isConstruct)) | (Tag.BER_TAG_MASK & tag))

def readApplicationTag(s: BinaryIO, tag: Tag) -> int:
    """
    Unpack an application tag and return the length of the application packet.
    :param s: stream
    :param tag: application tag.
    """
    byte = Uint8.unpack(s.read(1))
    
    if tag > 30:
        if byte != ((Class.BER_CLASS_APPL | PC.BER_CONSTRUCT) | Tag.BER_TAG_MASK):
            raise ValueError("Invalid BER tag")
        
        byte = Uint8.unpack(s.read(1))
        if byte != tag:
            raise ValueError("Unexpected application tag")
    else:
        if byte != ((Class.BER_CLASS_APPL | PC.BER_CONSTRUCT) | (tag & Tag.BER_TAG_MASK)):
            raise ValueError("Unexpected application tag")
        
    return readLength(s)

def writeApplicationTag(tag: Tag, size: int) -> bytes:
    """
    Pack an application tag.
    :param tag: application tag.
    :param size: the size of the application packet.
    """
    if tag > 30:
        return Uint8.pack((Class.BER_CLASS_APPL | PC.BER_CONSTRUCT) | Tag.BER_TAG_MASK) + Uint8.pack(tag) + writeLength(size)
    else:
        return Uint8.pack((Class.BER_CLASS_APPL | PC.BER_CONSTRUCT) | (Tag.BER_TAG_MASK & tag)) + writeLength(size)

def readContextualTag(s: BinaryIO, tag: Tag, isConstruct: bool) -> int:
    """
    Unpack contextual tag and return the tag length.
    :param s: stream
    :param tag: BER tag
    :param isConstruct: True if a construct is expected
    """
    byte = Uint8.unpack(s.read(1))
    if byte != ((Class.BER_CLASS_CTXT | berPC(isConstruct)) | (Tag.BER_TAG_MASK & tag)):
        raise ValueError("Unexpected contextual tag")
    return readLength(s)

def writeContextualTag(tag: Tag, size: int) -> bytes:
    """
    Pack contextual tag.
    :param tag: BER tag
    :param size: the size of the contextual packet.
    """
    return Uint8.pack((Class.BER_CLASS_CTXT | PC.BER_CONSTRUCT) | (Tag.BER_TAG_MASK & tag)) + writeLength(size)

def readBoolean(s: BinaryIO) -> bool:
    """
    Unpack a BER boolean
    :param s: stream
    """
    if not readUniversalTag(s, Tag.BER_TAG_BOOLEAN, False):
        raise ValueError("Bad boolean tag")

    size = readLength(s)
    if size != 1:
        raise ValueError("Bad boolean size")
    
    b = Uint8.unpack(s.read(1))
    return bool(b)

def writeBoolean(value: bool) -> bytes:
    """
    Pack a BER boolean
    """
    boolean = Uint8.pack(0xff if value else 0)
    return writeUniversalTag(Tag.BER_TAG_BOOLEAN, False) + writeLength(1) + boolean

def readInteger(s: BinaryIO) -> int:
    """
    Unpack a BER integer
    :param s: stream
    """
    if not readUniversalTag(s, Tag.BER_TAG_INTEGER, False):
        raise ValueError("Bad integer tag")
    
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
        raise ValueError("Wrong integer size")
    
def writeInteger(value: int) -> bytes:
    """
    Pack a BER integer
    """
    if value <= 0xff:
        return writeUniversalTag(Tag.BER_TAG_INTEGER, False) + writeLength(1) + Uint8.pack(value)
    elif value <= 0xffff:
        return writeUniversalTag(Tag.BER_TAG_INTEGER, False) + writeLength(2) + Uint16BE.pack(value)
    else:
        return writeUniversalTag(Tag.BER_TAG_INTEGER, False) + writeLength(4) + Uint32BE.pack(value)

def readOctetString(s: BinaryIO) -> bytes:
    """
    Unpack a BER octet string
    :param s: stream
    """
    if not readUniversalTag(s, Tag.BER_TAG_OCTET_STRING, False):
        raise ValueError("Bad octet string tag")
    
    size = readLength(s)
    return s.read(size)

def writeOctetString(value: bytes) -> bytes:
    """
    Pack a BER octet string
    """
    return writeUniversalTag(Tag.BER_TAG_OCTET_STRING, False) + writeLength(len(value)) + value

def readEnumeration(s: BinaryIO) -> int:
    """
    Unpack a BER enumeration value
    :param s: stream
    """
    if not readUniversalTag(s, Tag.BER_TAG_ENUMERATED, False):
        raise ValueError("Bad enumeration tag")
    
    if readLength(s) != 1:
        raise ValueError("Enumeration size must be 1")
    
    return Uint8.unpack(s.read(1))

def writeEnumeration(value: int) -> bytes:
    """
    Pack a BER enumeration value
    """
    return writeUniversalTag(Tag.BER_TAG_ENUMERATED, False) + writeLength(1) + Uint8.pack(value)
