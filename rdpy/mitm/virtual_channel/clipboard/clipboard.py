import logging

from rdpy.core.observer import Observer
from rdpy.enum.core import ParserMode
from rdpy.enum.rdp import RDPPlayerMessageType
from rdpy.pdu.rdp.virtual_channel.clipboard.paste import FormatDataResponsePDU


class MITMClipboardChannelObserver(Observer):
    """
    MITM observer to intercept clipboard data from the Clipboard virtual channel.
    """

    def __init__(self, layer, recorder, mode, **kwargs):
        """
        :type layer: rdpy.core.newlayer.Layer
        :type recorder: rdpy.recording.recorder.Recorder
        :type mode: rdpy.enum.core.ParserMode
        """
        Observer.__init__(self, **kwargs)
        self.peer = None
        self.layer = layer
        self.recorder = recorder
        self.mitm_log = logging.getLogger("mitm.clipboard.{}"
                                          .format("client" if mode == ParserMode.CLIENT else "server"))
        self.mitm_clipboard_log = logging.getLogger(self.mitm_log.name + ".data")

    def setPeer(self, peer):
        """
        Set this observer's peer observer.
        :param peer: other observer.
        :type peer: rdpy.mitm.observer.MITMVirtualChannelObserver
        """
        self.peer = peer
        peer.peer = self

    def onPDUReceived(self, pdu):
        """
        Called when a PDU on the observed layer is received.
        :param pdu: the PDU that was received.
        :type pdu: rdpy.pdu.rdp.virtual_channel.clipboard.clipboard.ClipboardPDU
        """
        if isinstance(pdu, FormatDataResponsePDU):
            self.mitm_clipboard_log.info(pdu.requestedFormatData)
            self.recorder.record(pdu, RDPPlayerMessageType.CLIPBOARD_DATA)
        else:
            self.mitm_log.debug("PDU received: {}".format(str(pdu.msgType)))

        if self.peer:
            self.peer.sendPDU(pdu)

    def sendPDU(self, pdu):
        """
        Send a clipboard PDU through the layer.
        :type pdu: rdpy.pdu.rdp.virtual_channel.clipboard.clipboard.ClipboardPDU
        """
        self.layer.send(pdu)


class MITMClientClipboardChannelObserver(MITMClipboardChannelObserver):

    def __init__(self, layer, recorder, **kwargs):
        MITMClipboardChannelObserver.__init__(self, layer, recorder, ParserMode.CLIENT, **kwargs)


class MITMServerClipboardChannelObserver(MITMClipboardChannelObserver):

    def __init__(self, layer, recorder, **kwargs):
        MITMClipboardChannelObserver.__init__(self, layer, recorder, ParserMode.SERVER, **kwargs)
