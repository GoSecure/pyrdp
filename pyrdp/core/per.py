#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
# Copyright (c) 2018, 2019, 2022 GoSecure Inc.
#
# This file is part of rdpy and PyRDP.
#
# PyRDP is free software: you can redistribute it and/or modify
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

from typing import BinaryIO, Tuple

from pyrdp.core.packing import Uint8, Uint16BE, Uint32BE


def readLength(s: BinaryIO) -> int:
    """
    Unpack a PER length indicator
    :param s: stream
    """
    byte = Uint8.unpack(s.read(1))

    if byte & 0x80:
        byte &= ~0x80
        return (byte << 8) + Uint8.unpack(s.read(1))
    else:
        return byte

def writeLength(value: int) -> bytes:
    """
    Pack a PER length indicator
    """
    if value > 0x7f:
        return Uint16BE.pack(value | 0x8000)
    else:
        return Uint8.pack(value)
    
def readChoice(s: BinaryIO) -> int:
    """
    Unpack a PER choice
    :param s: stream
    """
    return Uint8.unpack(s.read(1))

def writeChoice(choice: int) -> bytes:
    """
    Pack a PER choice
    :param choice: choice value
    """
    return Uint8.pack(choice)

def readSelection(s: BinaryIO) -> int:
    """
    Unpack a PER selection
    :param s: stream
    """
    return Uint8.unpack(s.read(1))

def writeSelection(selection: int) -> bytes:
    """
    Pack a PER selection
    :param selection: selection value
    """
    return Uint8.pack(selection)

def readNumberOfSet(s: BinaryIO) -> int:
    """
    Unpack a PER NumberOfSet
    :param s: stream
    """
    return Uint8.unpack(s.read(1))

def writeNumberOfSet(numberOfSet: int) -> bytes:
    """
    Pack a PER NumberOfSet
    :param numberOfSet: NumberOfSet value
    """
    return Uint8.pack(numberOfSet)

def readEnumeration(s: BinaryIO) -> int:
    """
    Unpack a PER enumeration format
    :param s: stream
    """
    return Uint8.unpack(s.read(1))

def writeEnumeration(enum: int) -> bytes:
    """
    Pack a PER enumeration
    :param enum: enumeration value
    """
    return Uint8.pack(enum)

def readInteger(s: BinaryIO) -> int:
    """
    Unpack a PER integer
    :param s: stream
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
        raise ValueError("invalid integer size %d" % size)

def writeInteger(value: int) -> bytes:
    """
    Pack a PER integer
    """
    if value <= 0xff:
        return writeLength(1) + Uint8.pack(value)
    elif value < 0xffff:
        return writeLength(2) + Uint16BE.pack(value)
    else:
        return writeLength(4) + Uint32BE.pack(value)

def readObjectIdentifier(s: BinaryIO):
    """
    Unpack a PER object identifier (tuple of 6 integers)
    :param s: stream
    :return: (int, int, int, int, int, int)
    """
    size = readLength(s)
    if size != 5:
        raise ValueError("Object identifier size must be 5 (got %d instead)" % size)
    
    a_oid = [0, 0, 0, 0, 0, 0]
    t12 = Uint8.unpack(s.read(1))
    a_oid[0] = t12 >> 4
    a_oid[1] = t12 & 0x0f
    a_oid[2] = Uint8.unpack(s.read(1))
    a_oid[3] = Uint8.unpack(s.read(1))
    a_oid[4] = Uint8.unpack(s.read(1))
    a_oid[5] = Uint8.unpack(s.read(1))
    return tuple(a_oid)

def writeObjectIdentifier(oid: Tuple[int, int, int, int, int, int]) -> bytes:
    """
    Pack a PER object identifier
    :param oid: object identifier (tuple of 6 integers)
    """
    return writeLength(5) + Uint8.pack((oid[0] << 4) & (oid[1] & 0x0f)) + b"".join(Uint8.pack(b) for b in oid[2 :])

def readNumericString(s: BinaryIO, minValue: int) -> str:
    """
    Unpack a PER numeric string
    :param s: stream
    :param minValue: minimum string length
    """
    length = readLength(s)
    length = (length + minValue + 1) // 2
    data = s.read(length)

    result = ""
    for b in data:
        c1 = (b >> 4) + 0x30
        c2 = (b & 0xf) + 0x30
        result += chr(c1) + chr(c2)
    
    return result

def writeNumericString(string: str, minValue: int) -> bytes:
    """
    Pack a PER numeric string
    :param string: numeric string
    :param minValue: minimum string length
    """
    length = len(string)
    mlength = minValue
    if length >= minValue:
        mlength = length - minValue
    
    result = b""
    
    for i in range(0, length, 2):
        c1 = ord(string[i : i + 1])
        if i + 1 < length:
            c2 = ord(string[i + 1 : i + 2])
        else:
            c2 = 0x30
        c1 = (c1 - 0x30) % 10
        c2 = (c2 - 0x30) % 10
        
        result += Uint8.pack((c1 << 4) | c2)
    
    return writeLength(mlength) + result

def readOctetStream(s: BinaryIO, minValue: int = 0) -> bytes:
    """
    Unpack a PER octet stream
    :param s: stream
    :param minValue: minimum string length
    """
    size = readLength(s) + minValue
    return s.read(size)

def writeOctetStream(bytes: bytes, minValue: int = 0) -> bytes:
    """
    Pack a PER octet stream
    :param bytes: octet stream
    :param minValue: minimum string length
    """
    length = len(bytes)
    mlength = minValue
    
    if length >= minValue:
        mlength = length - minValue
    
    return writeLength(mlength) + bytes

def writeOctetStreamAlternate(bytes: bytes) -> bytes:
    """
    Pack a PER octect stream with the alternate read length indicator
    :param bytes: octet stream
    Currently unused, implemented to match exactly what was sent by mstsc.exe
    on the wire.
    """
    length = len(bytes)
    return Uint16BE.pack(length | 0x8000) + bytes
