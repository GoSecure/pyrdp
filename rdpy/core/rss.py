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
Remote Session Scenario File format
Private protocol format to save events
"""
import socket

from rdpy.core.type import CompositeType, FactoryType, UInt8, UInt16Le, UInt32Le, String, sizeof, Stream
from rdpy.core import log, error
import time

class EventType(object):
    """
    @summary: event type
    """
    UPDATE = 0x0001
    SCREEN = 0x0002
    INFO = 0x0003
    CLOSE = 0x0004
    KEY_UNICODE = 0x0005
    KEY_SCANCODE = 0x0006

class UpdateFormat(object):
    """
    @summary: format of update bitmap
    """
    RAW = 0x01
    BMP = 0x02

class Event(CompositeType):
    """
    @summary: A recorded event
    """
    def __init__(self, event = None):
        CompositeType.__init__(self)
        self.type = UInt16Le(lambda:event.__class__._TYPE_)
        self.timestamp = UInt32Le()
        self.length = UInt32Le(lambda:(sizeof(self) - 10))

        def EventFactory():
            """
            @summary: Closure for event factory
            """
            for c in [UpdateEvent, ScreenEvent, InfoEvent, CloseEvent, KeyEventScancode, KeyEventUnicode]:
                if self.type.value == c._TYPE_:
                    return c(readLen = self.length)
            log.debug("unknown event type : %s"%hex(self.type.value))
            #read entire packet
            return String(readLen = self.length)

        if event is None:
            event = FactoryType(EventFactory)
        elif not "_TYPE_" in event.__class__.__dict__:
            raise error.InvalidExpectedDataException("Try to send an invalid event block")

        self.event = event

class UpdateEvent(CompositeType):
    """
    @summary: Update event
    """
    _TYPE_ = EventType.UPDATE
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.destLeft = UInt16Le()
        self.destTop = UInt16Le()
        self.destRight = UInt16Le()
        self.destBottom = UInt16Le()
        self.width = UInt16Le()
        self.height = UInt16Le()
        self.bpp = UInt8()
        self.format = UInt8()
        self.length = UInt32Le(lambda:sizeof(self.data))
        self.data = String(readLen = self.length)

class InfoEvent(CompositeType):
    """
    @summary: Info event
    """
    _TYPE_ = EventType.INFO
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.lenUsername = UInt16Le(lambda:sizeof(self.username))
        self.username = String(readLen = self.lenUsername)
        self.lenPassword = UInt16Le(lambda:sizeof(self.password))
        self.password = String(readLen = self.lenPassword)
        self.lenDomain = UInt16Le(lambda:sizeof(self.domain))
        self.domain = String(readLen = self.lenDomain)
        self.lenHostname = UInt16Le(lambda:sizeof(self.hostname))
        self.hostname = String(readLen = self.lenHostname)

class ScreenEvent(CompositeType):
    """
    @summary: screen information event
    """
    _TYPE_ = EventType.SCREEN
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.width = UInt16Le()
        self.height = UInt16Le()
        self.colorDepth = UInt8()

class CloseEvent(CompositeType):
    """
    @summary: end of session event
    """
    _TYPE_ = EventType.CLOSE
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)

class KeyEventUnicode(CompositeType):
    """
    @summary: keyboard event (keylogger) as unicode event
    """
    _TYPE_ = EventType.KEY_UNICODE
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.code = UInt32Le()
        self.isPressed = UInt8()

class KeyEventScancode(CompositeType):
    """
    @summary: keyboard event (keylogger)
    """
    _TYPE_ = EventType.KEY_SCANCODE
    def __init__(self, readLen = None):
        CompositeType.__init__(self, readLen = readLen)
        self.code = UInt32Le()
        self.isPressed = UInt8()

def timeMs():
    """
    @return: {int} time stamp in milliseconds
    """
    return int(time.time() * 1000)

class FileRecorder(object):
    """
    @summary: RSR File recorder
    """
    def __init__(self, f, write_method):
        """
        @param f: {file} file pointer use to write
        @param write_method: {callable} Method to call when writing to the recorder (ex socket.send(), file.write())
        """
        self._file = f
        self._write_method = write_method
        #init timer
        self._lastEventTimer = timeMs()

    def rec(self, event):
        """
        @summary: save event in file
        @param event: {UpdateEvent}
        """

        now = timeMs()
        #wrap around event message
        e = Event(event)
        #timestamp is time since last event
        e.timestamp.value = now - self._lastEventTimer
        self._lastEventTimer = now

        s = Stream()
        s.writeType(e)

        self._write_method(s.getvalue())

    def update(self, destLeft, destTop, destRight, destBottom, width, height, bpp, upateFormat, data):
        """
        @summary: record update event
        @param destLeft: {int} xmin position
        @param destTop: {int} ymin position
        @param destRight: {int} xmax position because RDP can send bitmap with padding
        @param destBottom: {int} ymax position because RDP can send bitmap with padding
        @param width: {int} width of bitmap
        @param height: {int} height of bitmap
        @param bpp: {int} number of bit per pixel
        @param upateFormat: {UpdateFormat} use RLE compression
        @param data: {str} bitmap data
        """
        updateEvent = UpdateEvent()
        updateEvent.destLeft.value = destLeft
        updateEvent.destTop.value = destTop
        updateEvent.destRight.value = destRight
        updateEvent.destBottom.value = destBottom
        updateEvent.width.value = width
        updateEvent.height.value = height
        updateEvent.bpp.value = bpp
        updateEvent.format.value = upateFormat
        updateEvent.data.value = data
        self.rec(updateEvent)

    def screen(self, width, height, colorDepth):
        """
        @summary: record resize event of screen (maybe first event)
        @param width: {int} width of screen
        @param height: {int} height of screen
        @param colorDepth: {int} colorDepth
        """
        screenEvent = ScreenEvent()
        screenEvent.width.value = width
        screenEvent.height.value = height
        screenEvent.colorDepth.value = colorDepth
        self.rec(screenEvent)

    def credentials(self, username, password, domain = "", hostname = ""):
        """
        @summary: Record informations event
        @param username: {str} username of session
        @param password: {str} password of session
        @param domain: {str} domain of session
        @param hostname: {str} hostname of session
        """
        infoEvent = InfoEvent()
        infoEvent.username.value = username
        infoEvent.password.value = password
        infoEvent.domain.value = domain
        infoEvent.hostname.value = hostname
        self.rec(infoEvent)

    def keyUnicode(self, code, isPressed):
        """
        @summary: record key event as unicode
        @param code: unicode code
        @param isPressed: True if a key press event
        """
        keyEvent = KeyEventUnicode()
        keyEvent.code.value = code
        keyEvent.isPressed.value = 0 if isPressed else 1
        self.rec(keyEvent)

    def keyScancode(self, code, isPressed):
        """
        @summary: record key event as scancode
        @param code: scancode code
        @param isPressed: True if a key press event
        """
        keyEvent = KeyEventScancode()
        keyEvent.code.value = code
        keyEvent.isPressed.value = 0 if isPressed else 1
        self.rec(keyEvent)

    def close(self):
        """
        @summary: end of scenario
        """
        self.rec(CloseEvent())


class SocketRecorder(FileRecorder):
    """
        Class that sends RDP events to an ip:port address
        as they arrive using TCP.
    """

    def __init__(self, ip, port):
        log.debug("Opening socket...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        super(SocketRecorder, self).__init__(s, s.send)


class FileReader(object):
    """
    @summary: RSR File reader
    """
    def __init__(self, f):
        """
        @param f: {file} file pointer use to read
        """
        self._s = Stream(f.read())

    def nextEvent(self):
        """
        @summary: read next event and return it
        """
        if self._s.eof():
            return None
        e = Event()
        self._s.readType(e)
        return e

def createRecorder(path):
    """
    @summary: open file from path and return FileRecorder
    @param path: {str} path of output file
    @return: {FileRecorder}
    """
    file_handle = open(path, "wb")
    return FileRecorder(file_handle, file_handle.write)


def createSocketRecorder(ip, port):
    """
        Returns a socket recorder to send RDP events to another address.
        :param ip: IP of the destination
        :param port: TCP port number of the destination
        :return: {SocketRecorder} the recorder object
    """
    return SocketRecorder(ip, port)

def createReader(path):
    """
    @summary: open file from path and return FileReader
    @param path: {str} path of input file
    @return: {FileReader}
    """
    with open(path, "rb") as f:
        return FileReader(f)
