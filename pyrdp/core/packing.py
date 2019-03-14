#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import struct
import typing

from pyrdp.core.stream import StrictStream


class Integer:
    FORMAT = ""

    @classmethod
    def unpack(cls, data: typing.Union[bytes, typing.BinaryIO, StrictStream, int]) -> int:
        """
        Unpack an integer from its binary representation.
        :param data: data to unpack from.
        :return: the integer's value.
        """
        try:
            if isinstance(data, bytes):
                return struct.unpack(cls.FORMAT, data)[0]
            elif isinstance(data, int):
                # Indexing bytes in Python 3 gives you an int instead of bytes object of length 1...
                return data
            else:
                length = {"b": 1, "h": 2, "i": 4, "q": 8}[cls.FORMAT[1].lower()]
                return struct.unpack(cls.FORMAT, data.read(length))[0]
        except struct.error as e:
            raise ValueError(str(e))

    @classmethod
    def pack(cls, value: int, stream: typing.Optional[typing.BinaryIO] = None) -> bytes:
        """
        Pack an integer to its binary representation.
        :param value: value to pack.
        :param stream: stream to pack to (optional).
        :return: the bytes representing the integer.
        """
        bytes = struct.pack(cls.FORMAT, value)

        if stream is not None:
            stream.write(bytes)

        return bytes

# 8 bits
class Int8(Integer):
    FORMAT = "<b"

class Uint8(Integer):
    FORMAT = "<B"

# 16 bits
class Int16LE(Integer):
    FORMAT = "<h"

class Int16BE(Integer):
    FORMAT = ">h"

class Uint16LE(Integer):
    FORMAT = "<H"

class Uint16BE(Integer):
    FORMAT = ">H"

# 32 bits
class Int32LE(Integer):
    FORMAT = "<i"

class Int32BE(Integer):
    FORMAT = ">i"

class Uint32LE(Integer):
    FORMAT = "<I"

class Uint32BE(Integer):
    FORMAT = ">I"

class Uint64LE(Integer):
    FORMAT = "<Q"
