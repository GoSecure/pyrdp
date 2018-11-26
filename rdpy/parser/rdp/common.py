from io import BytesIO

from rdpy.core.packing import Uint16LE
from rdpy.pdu.rdp.common import BitmapUpdateData


class RDPCommonParser:
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