from pyrdp.core.subject import ObservedBy
from pyrdp.enum.x224 import X224PDUType
from pyrdp.layer.layer import Layer, LayerStrictRoutedObserver
from pyrdp.parser.x224 import X224Parser
from pyrdp.pdu.x224 import X224DataPDU, X224ConnectionRequestPDU, X224ConnectionConfirmPDU, X224DisconnectRequestPDU, \
    X224ErrorPDU


class X224Observer(LayerStrictRoutedObserver):
    def __init__(self, **kwargs):
        LayerStrictRoutedObserver.__init__(self, {
            X224PDUType.X224_TPDU_CONNECTION_REQUEST: "onConnectionRequest",
            X224PDUType.X224_TPDU_CONNECTION_CONFIRM: "onConnectionConfirm",
            X224PDUType.X224_TPDU_DISCONNECT_REQUEST: "onDisconnectRequest",
            X224PDUType.X224_TPDU_DATA: "onData",
            X224PDUType.X224_TPDU_ERROR: "onError"
        }, **kwargs)

    def onConnectionRequest(self, pdu):
        """
        Called when a Connection Request PDU is received.
        :type pdu: X224ConnectionRequestPDU
        """
        raise NotImplementedError("Unhandled X224 Connection Request PDU")

    def onConnectionConfirm(self, pdu):
        """
        Called when a Connection Confirm PDU is received.
        :type pdu: X224ConnectionConfirmPDU
        """
        raise NotImplementedError("Unhandled X224 Connection Confirm PDU")

    def onDisconnectRequest(self, pdu):
        """
        Called when a Disconnect Request PDU is received.
        :type pdu: X224DisconnectRequestPDU
        """
        raise NotImplementedError("Unhandled X224 Disconnect Request PDU")

    def onData(self, pdu):
        """
        Called when a Data PDU is received.
        :type pdu: X224DataPDU
        """
        pass

    def onError(self, pdu):
        """
        Called when an Error PDU is received.
        :type pdu: X224ErrorPDU
        """
        raise NotImplementedError("Unhandled X224 Error PDU")


@ObservedBy(X224Observer)
class X224Layer(Layer):
    """
    Layer to handle X224-related traffic
    ObservedBy: X224Observer
    """

    def __init__(self):
        Layer.__init__(self, X224Parser(), hasNext=True)
        self.handlers = {}

    def recv(self, data):
        """
        Receive a X.224 message, decode its header, notify the observer and forward to the next layer
        if its a data PDU.
        :param data: The X.224 raw data (with header and payload)
        :type data: bytes
        """
        pdu = self.mainParser.parse(data)
        self.pduReceived(pdu, pdu.header == X224PDUType.X224_TPDU_DATA)

    def send(self, payload, roa=False, eot=True):
        """
        Encapsulate the payload in a X.224 Data PDU and send it to the transport (previous) layer.
        :type payload: bytes
        :param eot: End of transmission.
        :param roa: Request of acknowledgement
        """

        pdu = X224DataPDU(roa, eot, payload)
        self.previous.send(self.mainParser.write(pdu))

    def sendConnectionPDU(self, factory, payload, **kwargs):
        """
        :param factory: The PDU class to use to create the connection PDU
        :type factory: Class
        :type payload: bytes
        """
        credit = kwargs.pop("credit", 0)
        destination = kwargs.pop("destination", 0)
        source = kwargs.pop("source", 0)
        options = kwargs.pop("options", 0)

        pdu = factory(credit, destination, source, options, payload)
        self.previous.send(self.mainParser.write(pdu))

    def sendConnectionRequest(self, payload, **kwargs):
        """
        :param payload: the connection request payload.
        :type payload: bytes
        """
        self.sendConnectionPDU(X224ConnectionRequestPDU, payload, **kwargs)

    def sendConnectionConfirm(self, payload, **kwargs):
        """
        :param payload: the connection confirm payload.
        :type payload: bytes
        """
        self.sendConnectionPDU(X224ConnectionConfirmPDU, payload, **kwargs)

    def sendDisconnectRequest(self, reason, **kwargs):
        """
        :param reason: the disconnect reason.
        :type reason: int
        """
        destination = kwargs.pop("destination", 0)
        source = kwargs.pop("source", 0)
        payload = kwargs.pop("payload", "")

        pdu = X224DisconnectRequestPDU(destination, source, reason, payload)
        self.previous.send(self.mainParser.write(pdu))

    def sendError(self, cause, **kwargs):
        """
        :param cause: the error cause.
        :type cause: int
        """
        destination = kwargs.pop("destination", 0)

        pdu = X224ErrorPDU(destination, cause)
        self.previous.send(self.mainParser.write(pdu))
