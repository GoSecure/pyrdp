#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Int16LE, Uint16LE, Uint32LE, Uint64LE, Uint8
from pyrdp.enum import DeviceType, MouseButton, PlayerPDUType
from pyrdp.parser.segmentation import SegmentationParser
from pyrdp.pdu import Color, PlayerBitmapPDU, PlayerConnectionClosePDU, PlayerDeviceMappingPDU, \
    PlayerDirectoryListingRequestPDU, PlayerDirectoryListingResponsePDU, PlayerFileDescription, \
    PlayerFileDownloadCompletePDU, PlayerFileDownloadRequestPDU, PlayerFileDownloadResponsePDU, \
    PlayerForwardingStatePDU, PlayerKeyboardPDU, PlayerMouseButtonPDU, PlayerMouseMovePDU, PlayerMouseWheelPDU, \
    PlayerPDU, PlayerTextPDU


class PlayerParser(SegmentationParser):
    """
    Parser used for parsing messages to and from the PyRDP player. The player can be used by attackers to see the
    RDP session in real time and take control of the session.
    """

    def __init__(self):
        super().__init__()

        self.parsers = {
            PlayerPDUType.CONNECTION_CLOSE: self.parseConnectionClose,
            PlayerPDUType.MOUSE_MOVE: self.parseMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.parseMouseButton,
            PlayerPDUType.MOUSE_WHEEL: self.parseMouseWheel,
            PlayerPDUType.KEYBOARD: self.parseKeyboard,
            PlayerPDUType.TEXT: self.parseText,
            PlayerPDUType.FORWARDING_STATE: self.parseForwardingState,
            PlayerPDUType.BITMAP: self.parseBitmap,
            PlayerPDUType.DEVICE_MAPPING: self.parseDeviceMapping,
            PlayerPDUType.DIRECTORY_LISTING_REQUEST: self.parseDirectoryListingRequest,
            PlayerPDUType.DIRECTORY_LISTING_RESPONSE: self.parseDirectoryListingResponse,
            PlayerPDUType.FILE_DOWNLOAD_REQUEST: self.parseFileDownloadRequest,
            PlayerPDUType.FILE_DOWNLOAD_RESPONSE: self.parseFileDownloadResponse,
            PlayerPDUType.FILE_DOWNLOAD_COMPLETE: self.parseFileDownloadComplete,
        }

        self.writers = {
            PlayerPDUType.CONNECTION_CLOSE: self.writeConnectionClose,
            PlayerPDUType.MOUSE_MOVE: self.writeMouseMove,
            PlayerPDUType.MOUSE_BUTTON: self.writeMouseButton,
            PlayerPDUType.MOUSE_WHEEL: self.writeMouseWheel,
            PlayerPDUType.KEYBOARD: self.writeKeyboard,
            PlayerPDUType.TEXT: self.writeText,
            PlayerPDUType.FORWARDING_STATE: self.writeForwardingState,
            PlayerPDUType.BITMAP: self.writeBitmap,
            PlayerPDUType.DEVICE_MAPPING: self.writeDeviceMapping,
            PlayerPDUType.DIRECTORY_LISTING_REQUEST: self.writeDirectoryListingRequest,
            PlayerPDUType.DIRECTORY_LISTING_RESPONSE: self.writeDirectoryListingResponse,
            PlayerPDUType.FILE_DOWNLOAD_REQUEST: self.writeFileDownloadRequest,
            PlayerPDUType.FILE_DOWNLOAD_RESPONSE: self.writeFileDownloadResponse,
            PlayerPDUType.FILE_DOWNLOAD_COMPLETE: self.writeFileDownloadComplete,
        }


    def getPDULength(self, data: bytes) -> int:
        return Uint64LE.unpack(data[: 8])

    def isCompletePDU(self, data: bytes) -> bool:
        if len(data) < 8:
            return False

        return len(data) >= self.getPDULength(data)


    def parse(self, data: bytes) -> PlayerPDU:
        stream = BytesIO(data)

        length = Uint64LE.unpack(stream)
        pduType = PlayerPDUType(Uint16LE.unpack(stream))
        timestamp = Uint64LE.unpack(stream)

        if pduType in self.parsers:
            return self.parsers[pduType](stream, timestamp)

        payload = stream.read(length - 18)
        return PlayerPDU(pduType, timestamp, payload)

    def write(self, pdu: PlayerPDU) -> bytes:
        substream = BytesIO()

        Uint16LE.pack(pdu.header, substream)
        Uint64LE.pack(pdu.timestamp, substream)

        if pdu.header in self.writers:
            self.writers[pdu.header](pdu, substream)

        substream.write(pdu.payload)
        substreamValue = substream.getvalue()

        stream = BytesIO()
        Uint64LE.pack(len(substreamValue) + 8, stream)
        stream.write(substreamValue)

        return stream.getvalue()


    def parseConnectionClose(self, _: BytesIO, timestamp: int) -> PlayerConnectionClosePDU:
        return PlayerConnectionClosePDU(timestamp)

    def writeConnectionClose(self, pdu: PlayerConnectionClosePDU, stream: BytesIO):
        pass


    def parseMousePosition(self, stream: BytesIO) -> (int, int):
        x = Uint16LE.unpack(stream)
        y = Uint16LE.unpack(stream)
        return x, y

    def writeMousePosition(self, x: int, y: int, stream: BytesIO):
        Uint16LE.pack(x, stream)
        Uint16LE.pack(y, stream)


    def parseMouseMove(self, stream: BytesIO, timestamp: int) -> PlayerMouseMovePDU:
        x, y = self.parseMousePosition(stream)
        return PlayerMouseMovePDU(timestamp, x, y)

    def writeMouseMove(self, pdu: PlayerMouseMovePDU, stream: BytesIO):
        self.writeMousePosition(pdu.x, pdu.y, stream)


    def parseMouseButton(self, stream: BytesIO, timestamp: int) -> PlayerMouseButtonPDU:
        x, y = self.parseMousePosition(stream)
        button = MouseButton(Uint8.unpack(stream))
        pressed = Uint8.unpack(stream)
        return PlayerMouseButtonPDU(timestamp, x, y, button, bool(pressed))

    def writeMouseButton(self, pdu: PlayerMouseButtonPDU, stream: BytesIO):
        self.writeMousePosition(pdu.x, pdu.y, stream)
        Uint8.pack(pdu.button.value, stream)
        Uint8.pack(int(pdu.pressed), stream)


    def parseMouseWheel(self, stream: BytesIO, timestamp: int) -> PlayerMouseWheelPDU:
        x, y = self.parseMousePosition(stream)
        delta = Int16LE.unpack(stream)
        horizontal = bool(Uint8.unpack(stream))
        return PlayerMouseWheelPDU(timestamp, x, y, delta, horizontal)

    def writeMouseWheel(self, pdu: PlayerMouseWheelPDU, stream: BytesIO):
        self.writeMousePosition(pdu.x, pdu.y, stream)
        Int16LE.pack(pdu.delta, stream)
        Uint8.pack(int(pdu.horizontal), stream)


    def parseKeyboard(self, stream: BytesIO, timestamp: int) -> PlayerKeyboardPDU:
        code = Uint16LE.unpack(stream)
        released = bool(Uint8.unpack(stream))
        extended = bool(Uint8.unpack(stream))
        return PlayerKeyboardPDU(timestamp, code, released, extended)

    def writeKeyboard(self, pdu: PlayerKeyboardPDU, stream: BytesIO):
        Uint16LE.pack(pdu.code, stream)
        Uint8.pack(int(pdu.released), stream)
        Uint8.pack(int(pdu.extended), stream)


    def parseText(self, stream: BytesIO, timestamp: int) -> PlayerTextPDU:
        length = Uint8.unpack(stream)
        character = stream.read(length).decode()
        released = Uint8.unpack(stream)
        return PlayerTextPDU(timestamp, character, bool(released))

    def writeText(self, pdu: PlayerTextPDU, stream: BytesIO):
        encoded = pdu.character[: 1].encode()

        Uint8.pack(len(encoded), stream)
        stream.write(encoded)
        Uint8.pack(int(pdu.released), stream)


    def parseForwardingState(self, stream: BytesIO, timestamp: int) -> PlayerForwardingStatePDU:
        forwardInput = bool(Uint8.unpack(stream))
        forwardOutput = bool(Uint8.unpack(stream))
        return PlayerForwardingStatePDU(timestamp, forwardInput, forwardOutput)

    def writeForwardingState(self, pdu: PlayerForwardingStatePDU, stream: BytesIO):
        Uint8.pack(int(pdu.forwardInput), stream)
        Uint8.pack(int(pdu.forwardOutput), stream)


    def parseColor(self, stream: BytesIO) -> Color:
        r = Uint8.unpack(stream)
        g = Uint8.unpack(stream)
        b = Uint8.unpack(stream)
        a = Uint8.unpack(stream)
        return Color(r, g, b, a)

    def writeColor(self, color: Color, stream: BytesIO):
        Uint8.pack(color.r, stream)
        Uint8.pack(color.g, stream)
        Uint8.pack(color.b, stream)
        Uint8.pack(color.a, stream)

    def parseBitmap(self, stream: BytesIO, timestamp: int) -> PlayerBitmapPDU:
        width = Uint32LE.unpack(stream)
        height = Uint32LE.unpack(stream)
        pixels = stream.read(width * height * 4)
        return PlayerBitmapPDU(timestamp, width, height, pixels)

    def writeBitmap(self, pdu: PlayerBitmapPDU, stream: BytesIO):
        Uint32LE.pack(pdu.width, stream)
        Uint32LE.pack(pdu.height, stream)
        stream.write(pdu.pixels)


    def parseDeviceMapping(self, stream: BytesIO, timestamp: int) -> PlayerDeviceMappingPDU:
        deviceID = Uint32LE.unpack(stream)
        deviceType = DeviceType(Uint32LE.unpack(stream))
        nameLength = Uint32LE.unpack(stream)
        name = stream.read(nameLength).decode()
        return PlayerDeviceMappingPDU(timestamp, deviceID, deviceType, name)

    def writeDeviceMapping(self, pdu: PlayerDeviceMappingPDU, stream: BytesIO):
        name = pdu.name.encode()

        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(pdu.deviceType, stream)
        Uint32LE.pack(len(name), stream)
        stream.write(name)


    def parseDirectoryListingRequest(self, stream: BytesIO, timestamp: int) -> PlayerDirectoryListingRequestPDU:
        deviceID = Uint32LE.unpack(stream)
        length = Uint32LE.unpack(stream)
        path = stream.read(length).decode()
        return PlayerDirectoryListingRequestPDU(timestamp, deviceID, path)

    def writeDirectoryListingRequest(self, pdu: PlayerDirectoryListingRequestPDU, stream: BytesIO):
        path = pdu.path.encode()

        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(len(path), stream)
        stream.write(path)


    def parseFileDescription(self, stream: BytesIO) -> PlayerFileDescription:
        length = Uint32LE.unpack(stream)
        path = stream.read(length).decode()
        isDirectory = bool(Uint8.unpack(stream))

        return PlayerFileDescription(path, isDirectory)

    def writeFileDescription(self, description: PlayerFileDescription, stream: BytesIO):
        path = description.path.encode()

        Uint32LE.pack(len(path), stream)
        stream.write(path)
        Uint8.pack(int(description.isDirectory), stream)


    def parseDirectoryListingResponse(self, stream: BytesIO, timestamp: int) -> PlayerDirectoryListingResponsePDU:
        deviceID = Uint32LE.unpack(stream)
        count = Uint32LE.unpack(stream)
        fileDescriptions = [self.parseFileDescription(stream) for _ in range(count)]

        return PlayerDirectoryListingResponsePDU(timestamp, deviceID, fileDescriptions)

    def writeDirectoryListingResponse(self, pdu: PlayerDirectoryListingResponsePDU, stream: BytesIO):
        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(len(pdu.fileDescriptions), stream)

        for description in pdu.fileDescriptions:
            self.writeFileDescription(description, stream)


    def parseFileDownloadRequest(self, stream: BytesIO, timestamp: int) -> PlayerFileDownloadRequestPDU:
        deviceID = Uint32LE.unpack(stream)
        length = Uint32LE.unpack(stream)
        path = stream.read(length).decode()
        return PlayerFileDownloadRequestPDU(timestamp, deviceID, path)

    def writeFileDownloadRequest(self, pdu: PlayerFileDownloadRequestPDU, stream: BytesIO):
        path = pdu.path.encode()

        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(len(path), stream)
        stream.write(path)


    def parseFileDownloadResponse(self, stream: BytesIO, timestamp: int) -> PlayerFileDownloadResponsePDU:
        deviceID = Uint32LE.unpack(stream)
        pathLength = Uint32LE.unpack(stream)
        path = stream.read(pathLength).decode()
        offset = Uint64LE.unpack(stream)
        payloadLength = Uint32LE.unpack(stream)
        payload = stream.read(payloadLength)

        return PlayerFileDownloadResponsePDU(timestamp, deviceID, path, offset, payload)

    def writeFileDownloadResponse(self, pdu: PlayerFileDownloadResponsePDU, stream: BytesIO):
        path = pdu.path.encode()

        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(len(path), stream)
        stream.write(path)
        Uint64LE.pack(pdu.offset, stream)
        Uint32LE.pack(len(pdu.payload), stream)
        stream.write(pdu.payload)


    def parseFileDownloadComplete(self, stream: BytesIO, timestamp: int) -> PlayerFileDownloadCompletePDU:
        deviceID = Uint32LE.unpack(stream)
        length = Uint32LE.unpack(stream)
        path = stream.read(length).decode()
        error = Uint32LE.unpack(stream)
        return PlayerFileDownloadCompletePDU(timestamp, deviceID, path, error)

    def writeFileDownloadComplete(self, pdu: PlayerFileDownloadCompletePDU, stream: BytesIO):
        path = pdu.path.encode()

        Uint32LE.pack(pdu.deviceID, stream)
        Uint32LE.pack(len(path), stream)
        stream.write(path)
        Uint32LE.pack(pdu.error, stream)