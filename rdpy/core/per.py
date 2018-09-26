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
PER encoding / decoding functions
"""

from rdpy.core.packing import Uint8, Uint16BE, Uint32BE
from rdpy.core.error import InvalidValue, InvalidExpectedDataException

def readLength(s):
    """
    @summary: Decode a PER length indicator
    @param s: stream
    @return: int
    """
    byte = Uint8.unpack(s.read(1))
    size = 0
    if byte & 0x80:
        byte &= ~0x80
        return (byte << 8) + Uint8.unpack(s.read(1))
    else:
        return byte

def writeLength(value):
    """
    @summary: Encode a PER length indicator
    @param value: int
    @return: str
    """
    if value > 0x7f:
        return Uint16BE.pack(value | 0x8000)
    else:
        return Uint8.pack(value)
    
def readChoice(s):
    """
    @summary: Decode PER choice
    @param s: stream
    @return: int
    """
    return Uint8.unpack(s.read(1))

def writeChoice(choice):
    """
    @summary: Encode PER choice
    @param choice: choice value
    @return: str
    """
    return Uint8.pack(choice)

def readSelection(s):
    """
    @summary: Decode PER selection
    @param s: stream
    @return: int
    """
    return Uint8.unpack(s.read(1))

def writeSelection(selection):
    """
    @summary: Encode PER selection
    @param selection: selection value
    @return: str
    """
    return Uint8.pack(selection)

def readNumberOfSet(s):
    """
    @summary: Decode PER NumberOfSet
    @param s: stream
    @return: int
    """
    return Uint8.unpack(s.read(1))

def writeNumberOfSet(numberOfSet):
    """
    @summary: Encode PER NumberOfSet
    @param numberOfSet: NumberOfSet value
    @return: str
    """
    return Uint8.pack(numberOfSet)

def readEnumeration(s):
    """
    @summary: Decode PER enumeration format
    @param s: stream
    @return: int
    """
    return Uint8.unpack(s.read(1))

def writeEnumerate(enum):
    """
    @summary: Encode PER enumeration
    @param enum: enumeration value
    @return: str
    """
    return Uint8.pack(enum)

def readInteger(s):
    """
    @summary: Decode PER integer
    @param s: stream
    @return: int
    @raise InvalidValue: if the size of the integer is invalid
    """
    size = readLength(s)

    if size == 1:
        return Uint8.unpack(s.read(1))
    elif size == 2:
        return Uint16BE.unpack(s.read(2))
    elif size == 4:
        return Uint32BE.unpack(s.read(4))
    else:
        raise InvalidValue("invalid integer size %d" % size)

def writeInteger(value):
    """
    @summary: Encode PER integer
    @param value: int
    @return: str
    """
    if value <= 0xff:
        return writeLength(1) + Uint8(value)
    elif value < 0xffff:
        return writeLength(2) + Uint16BE(value)
    else:
        return writeLength(4) + Uint32BE(value)

def readObjectIdentifier(s):
    """
    @summary: Decode PER object identifier
    @param s: stream
    @return: object identifier (tuple of 6 elements)
    """
    size = readLength(s)
    if size != 5:
        raise InvalidValue("Object identifier size must be 5 (got %d instead)" % size)
    
    a_oid = [0, 0, 0, 0, 0, 0]
    t12 = Uint8.unpack(s.read(1))
    a_oid[0] = t12 >> 4
    a_oid[1] = t12 & 0x0f
    a_oid[2] = Uint8.unpack(s.read(1))
    a_oid[3] = Uint8.unpack(s.read(1))
    a_oid[4] = Uint8.unpack(s.read(1))
    a_oid[5] = Uint8.unpack(s.read(1))
    return a_oid

def writeObjectIdentifier(oid):
    """
    @summary: Encode PER object identifier
    @param oid: object identifier (tuple of 6 elements)
    @return: str
    """
    return writeLength(5) + Uint8.pack((oid[0] << 4) & (oid[1] & 0x0f)) + "".join(Uint8.pack(b) for b in oid[2 :])

def readNumericString(s, minValue):
    """
    @summary: Decode PER numeric string
    @param s: stream
    @param minValue: minimum string length
    @return: str
    """
    length = readLength(s)
    length = (length + minValue + 1) / 2
    data = s.read(length)

    result = ""
    for b in data:
        b = Uint8.unpack(b)
        c1 = (b >> 4) + 0x30
        c2 = (b & 0xf) + 0x30
        result += chr(c1) + chr(c2)
    
    return result

def writeNumericString(nStr, minValue):
    """
    @summary: Encode PER numeric string
    @param str: numeric string
    @param min: minimum string length
    @return: str
    """
    length = len(nStr)
    mlength = minValue
    if length >= minValue:
        mlength = length - minValue
    
    result = ""
    
    for i in range(0, length, 2):
        c1 = ord(nStr[i])
        if i + 1 < length:
            c2 = ord(nStr[i + 1])
        else:
            c2 = 0x30
        c1 = (c1 - 0x30) % 10
        c2 = (c2 - 0x30) % 10
        
        result += Uint8.pack((c1 << 4) | c2)
    
    return writeLength(mlength) + result

def readOctetStream(s, minValue = 0):
    """
    @summary: Decode PER octet stream
    @param s: stream
    @param minValue: minimum string length
    @return: str
    """
    size = readLength(s) + minValue
    return "".join(Uint8.unpack(s.read(1)) for _ in range(size))

def writeOctetStream(oStr, minValue = 0):
    """
    @summary: Encode PER octet stream
    @param oStr: octet stream
    @param minValue: minimum string length
    @return: str
    """
    length = len(oStr)
    mlength = minValue
    
    if length >= minValue:
        mlength = length - minValue
    
    return writeLength(mlength) + oStr
