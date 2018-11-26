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
from queue import Queue
from typing import BinaryIO

from rdpy.core.stream import ByteStream
from rdpy.enum.core import ParserMode
from rdpy.layer.recording import RDPPlayerMessageLayer, RDPPlayerMessageObserver
from rdpy.layer.tpkt import TPKTLayer
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.data import RDPDataParser
from rdpy.parser.rdp.fastpath import RDPBasicFastPathParser
from rdpy.parser.rdp.virtual_channel.clipboard import ClipboardParser


class Reader(RDPPlayerMessageObserver):
    """
    Base class to manage parsing of packets to read RDP events for a Player.
    """

    def __init__(self, **kwargs):
        RDPPlayerMessageObserver.__init__(self, **kwargs)
        self.eventQueue = Queue()
        self.tpkt = TPKTLayer()
        self.message = RDPPlayerMessageLayer()

        self.tpkt.setNext(self.message)
        self.message.addObserver(self)

        self.inputParser = RDPBasicFastPathParser(ParserMode.SERVER)
        self.outputParser = RDPBasicFastPathParser(ParserMode.CLIENT)
        self.clientInfoParser = RDPClientInfoParser()
        self.dataParser = RDPDataParser()
        self.clipboardParser = ClipboardParser()

    def onConnectionClose(self, pdu):
        timestamp = pdu.timestamp
        self.eventQueue.put((timestamp, None))

    def onClientInfo(self, pdu):
        timestamp = pdu.timestamp
        pdu = self.clientInfoParser.parse(pdu.payload)
        self.eventQueue.put((timestamp, pdu))

    def onConfirmActive(self, pdu):
        timestamp = pdu.timestamp
        pdu = self.dataParser.parse(pdu.payload)
        self.eventQueue.put((timestamp, pdu))

    def onInput(self, pdu):
        timestamp = pdu.timestamp
        pdu = self.inputParser.parse(pdu.payload)
        self.eventQueue.put((timestamp, pdu))

    def onOutput(self, pdu):
        timestamp = pdu.timestamp
        pdu = self.outputParser.parse(pdu.payload)
        self.eventQueue.put((timestamp, pdu))

    def onClipboardData(self, pdu):
        timestamp = pdu.timestamp
        pdu = self.clipboardParser.parse(pdu.payload)
        self.eventQueue.put((timestamp, pdu))


class FileReader(Reader):
    """
    RDP connections file reader.
    """
    def __init__(self, f, **kwargs):
        """
        :type f: BinaryIO
        """
        Reader.__init__(self, **kwargs)
        self.file = f

    def nextEvent(self):
        """
        :return: The next RDP Event to read.
        """
        if self.eventQueue.empty():
            self.tpkt.recv(self._s.read())

        # After tpkt_layer.recv, new events should be in the Queue. if not, its over.
        if not self.eventQueue.empty():
            return self.eventQueue.get()

    def reset(self):
        """
        Resets the reader's cursor to the beginning of the stream.
        """
        self._s.pos = 0



class RssAdaptor:
    def sendMouseEvent(self, e, isPressed):
        """ Not Handled """
    def sendKeyEvent(self, e, isPressed):
        """ Not Handled """
    def sendWheelEvent(self, e):
        """ Not Handled """
    def closeEvent(self, e):
        """ Not Handled """


def createFileReader(path):
    """
    @summary: open file from path and return FileReader
    @param path: {str} path of input file
    @return: {FileReader}
    """
    with open(path, "rb") as f:
            return FileReader(f)