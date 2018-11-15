from rdpy.core import log

from rdpy.core.newlayer import Layer
from rdpy.layer.rdp.data import RDPBaseDataLayer
from rdpy.layer.rdp.recording import RDPPlayerMessageTypeLayer
from rdpy.layer.tpkt import TPKTLayer


class Recorder:
    """
    Class that manages recording of RDP events using the provided
    transport layers. Those transport layers are the ones that will
    receive binary data and handle them as they wish. They perform the actual recording.
    """

    def __init__(self, transport_layers, parser):
        """
        :type transport_layers: list
        """
        self.rdpLayers = []
        for transport_layer in transport_layers:
            tpktLayer = TPKTLayer()
            rdpPlayerMessageTypeLayer = RDPPlayerMessageTypeLayer()
            rdp = RDPBaseDataLayer(parser)

            transport_layer.setNext(tpktLayer)
            tpktLayer.setNext(rdpPlayerMessageTypeLayer)
            rdpPlayerMessageTypeLayer.setNext(rdp)
            self.rdpLayers.append(rdp)

    def record(self, pdu, messageType):
        """
        Encapsulate the pdu properly, then record the data
        :type messageType: rdpy.enum.rdp.RDPPlayerMessageType
        :type pdu: rdpy.pdu.base_pdu.PDU
        """
        for rdpLayer in self.rdpLayers:
            rdpLayer.previous.setMessageType(messageType)
            rdpLayer.sendPDU(pdu, messageType)


class FileLayer(Layer):
    """
    Layer that saves RDP events to a file for later replay.
    """

    def __init__(self, fileHandle):
        """
        :type fileHandle: BinaryIO
        """
        super(FileLayer, self).__init__()
        self.file_descriptor = fileHandle

    def send(self, data):
        """
        Save data to the file.
        :type data: str
        """
        log.debug("writing {} to {}".format(data, self.file_descriptor))
        self.file_descriptor.write(data)


class SocketLayer(Layer):
    """
    Layer that sends RDP events to a network socket for live play.
    """

    def __init__(self, socket):
        """
        :type socket: socket.socket
        """
        super(SocketLayer, self).__init__()
        self.socket = socket
        self.isConnected = True

    def send(self, data):
        """
        Send data through the socket
        :type data: str
        """
        if self.isConnected:
            try:
                log.debug("sending {} to {}".format(data, self.socket.getpeername()))
                self.socket.send(data)
            except Exception as e:
                log.error("Cant send data over the network socket: {}".format(e.message))
                self.isConnected = False
