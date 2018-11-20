#!/usr/bin/env python2
import struct


class Integer:
    @classmethod
    def unpack(cls, data):
        """
        :param data: data to unpack from.
        :type data: str | file | StringIO.StringIO
        :return: int
        """
        try:
            if isinstance(data, str):
                return struct.unpack(cls.FORMAT, data)[0]
            else:
                length = {"b": 1, "h": 2, "i": 4}[cls.FORMAT[1].lower()]
                return struct.unpack(cls.FORMAT, data.read(length))[0]
        except struct.error as e:
            raise ValueError(e.message)

    @classmethod
    def pack(cls, value, stream = None):
        """
        :param value: value to pack
        :type value: int | str
        :param stream: stream to pack to (optional)
        :type stream: file | StringIO.StringIO | None
        :return: str | None
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
