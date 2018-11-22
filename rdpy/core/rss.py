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
from Queue import Queue

from typing import BinaryIO

from rdpy.core import log
from rdpy.core.observer import Observer
from rdpy.core.stream import ByteStream
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.layer.recording import RDPPlayerMessageTypeLayer
from rdpy.layer.tpkt import TPKTLayer
from rdpy.parser.rdp.client_info import RDPClientInfoParser
from rdpy.parser.rdp.data import RDPDataParser
from rdpy.parser.rdp.fastpath import RDPBasicFastPathParser
from rdpy.parser.rdp.virtual_channel.clipboard import ClipboardParser


class Reader(Observer):
    """
    Base class to manage parsing of packets to read RDP events for a Player.
    """

    def __init__(self, **kwargs):
        Observer.__init__(self, **kwargs)
        self.tpkt_layer = TPKTLayer()
        self.rdp_player_event_type_layer = RDPPlayerMessageTypeLayer()
        self.tpkt_layer.setNext(self.rdp_player_event_type_layer)
        self.rdp_player_event_type_layer.addObserver(self)
        self._events_queue = Queue()
        self.rdp_server_fastpath_parser = RDPBasicFastPathParser(ParserMode.SERVER)
        self.rdp_client_fastpath_parser = RDPBasicFastPathParser(ParserMode.CLIENT)
        self.rdp_client_info_parser = RDPClientInfoParser()
        self.rdp_data_parser = RDPDataParser()
        self.clipboardParser = ClipboardParser()

    def onPDUReceived(self, pdu):
        """
        Put the PDU in the events queue after parsing the provided pdu's payload.
        :type pdu: rdpy.pdu.rdp.recording.RDPPlayerMessagePDU
        """
        try:
            if pdu.type == RDPPlayerMessageType.INPUT:
                rdpPdu = self.rdp_server_fastpath_parser.parse(pdu.payload)
            elif pdu.type == RDPPlayerMessageType.OUTPUT:
                rdpPdu = self.rdp_client_fastpath_parser.parse(pdu.payload)
            elif pdu.type == RDPPlayerMessageType.CLIENT_INFO:
                rdpPdu = self.rdp_client_info_parser.parse(pdu.payload)
            elif pdu.type == RDPPlayerMessageType.CONFIRM_ACTIVE:
                rdpPdu = self.rdp_data_parser.parse(pdu.payload)
            elif pdu.type == RDPPlayerMessageType.CONNECTION_CLOSE:
                rdpPdu = None
            elif pdu.type == RDPPlayerMessageType.CLIPBOARD_DATA:
                rdpPdu = self.clipboardParser.parse(pdu.payload)
            else:
                raise ValueError("Incorrect RDPPlayerMessageType received: {}".format(pdu.type))
            pdu.payload = rdpPdu
            self._events_queue.put(pdu)
            pass
        except Exception as e:
            log.error("Error occured when parsing RDP event: {}".format(e.message))


class FileReader(Reader):
    """
    RDP connections file reader.
    """
    def __init__(self, f, **kwargs):
        """
        :type f: BinaryIO
        """
        Reader.__init__(self, **kwargs)
        self._s = ByteStream(f.read())

    def nextEvent(self):
        """
        :return: The next RDP Event to read.
        """
        if self._events_queue.empty():
            self.tpkt_layer.recv(self._s.read())

        # After tpkt_layer.recv, new events should be in the Queue. if not, its over.
        if not self._events_queue.empty():
            return self._events_queue.get()

    def reset(self):
        """
        Resets the reader's cursor to the beginning of the stream.
        """
        self._s.pos = 0


class SocketReader(Reader):
    """
    Class to read RDP events from a live connection using a network socket.
    """

    def __init__(self, socket, **kwargs):
        """
        :type socket: socket.socket
        """
        Reader.__init__(self, **kwargs)
        self._socket = socket

    def nextEvent(self):
        """
        :return: The next RDP Event to read.
        """

        if self._events_queue.empty():
            try:
                self.tpkt_layer.recvWithSocket(self._socket)
            except Exception as e:
                log.error("Error while receiving data from the network socket: {}".format(e.message))

        # After tpkt_layer.recv, new events should be in the Queue. if not, its over.
        if not self._events_queue.empty():
            event = self._events_queue.get()
            if event.type == RDPPlayerMessageType.CONNECTION_CLOSE:
                return None
            else:
                return event

    def close(self):
        self._socket.close()


def createFileReader(path):
    """
    @summary: open file from path and return FileReader
    @param path: {str} path of input file
    @return: {FileReader}
    """
    with open(path, "rb") as f:
            return FileReader(f)

