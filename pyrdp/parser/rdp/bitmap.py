#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE
from pyrdp.pdu import BitmapUpdateData


class BitmapParser:
    def parseBitmapUpdateData(self, data: bytes) -> [BitmapUpdateData]:
        stream = BytesIO(data)

        bitmapUpdates = []
        numberRectangles = Uint16LE.unpack(stream.read(2))

        for i in range(numberRectangles):
            destLeft = Uint16LE.unpack(stream.read(2))
            destTop = Uint16LE.unpack(stream.read(2))
            destRight = Uint16LE.unpack(stream.read(2))
            destBottom = Uint16LE.unpack(stream.read(2))
            width = Uint16LE.unpack(stream.read(2))
            height = Uint16LE.unpack(stream.read(2))
            bitsPerPixel = Uint16LE.unpack(stream.read(2))
            flags = Uint16LE.unpack(stream.read(2))
            bitmapLength = Uint16LE.unpack(stream.read(2))
            bitmapData = stream.read(bitmapLength)
            bitmapUpdates.append(BitmapUpdateData(destLeft, destTop, destRight, destBottom, width, height, bitsPerPixel,
                                               flags, bitmapData))

        return bitmapUpdates

    def writeBitmapUpdateData(self, bitmap: BitmapUpdateData) -> bytes:
        stream = BytesIO()
        Uint16LE.pack(bitmap.destLeft, stream)
        Uint16LE.pack(bitmap.destTop, stream)
        Uint16LE.pack(bitmap.destRight, stream)
        Uint16LE.pack(bitmap.destBottom, stream)
        Uint16LE.pack(bitmap.width, stream)
        Uint16LE.pack(bitmap.heigth, stream)
        Uint16LE.pack(bitmap.bitsPerPixel, stream)
        Uint16LE.pack(bitmap.flags, stream)
        Uint16LE.pack(len(bitmap.bitmapData), stream)
        stream.write(bitmap.bitmapData)
        return stream.getvalue()