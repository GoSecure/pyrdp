from StringIO import StringIO

from rdpy.core.packing import Uint8, Uint16BE



class X224Header:
    """
    @summary: X224 header codes
    """
    X224_TPDU_CONNECTION_REQUEST = 0x0E
    X224_TPDU_CONNECTION_CONFIRM = 0x0D
    X224_TPDU_DISCONNECT_REQUEST = 0x08
    X224_TPDU_DATA = 0x0F
    X224_TPDU_ERROR = 0x07



class X224PDU:
    """
    @summary: Base class for X224 PDUs
    """
    def __init__(self, length, header, payload):
        self.length = length
        self.header = header
        self.payload = payload

class X224ConnectionRequest(X224PDU):
    """
    @summary: X224 Connection Request PDU
    """
    def __init__(self, credit, destination, source, options, payload):
        super(X224PDU, self).__init__(len(payload) + 6, X224Header.X224_TPDU_CONNECTION_REQUEST, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options

class X224ConnectionConfirm(X224PDU):
    """
    @summary: X224 Connection Confirm PDU
    """
    def __init__(self, credit, destination, source, options, payload):
        super(X224PDU, self).__init__(len(payload) + 6, X224Header.X224_TPDU_CONNECTION_CONFIRM, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options

class X224DisconnectRequest(X224PDU):
    """
    @summary: X224 Disconnect Request PDU
    """
    def __init__(self, destination, source, reason, payload):
        super(X224PDU, self).__init__(len(payload) + 6, X224Header.X224_TPDU_DISCONNECT_REQUEST, payload)
        self.destination = destination
        self.source = source
        self.reason = reason

class X224Data(X224PDU):
    """
    @summary: X224 Data PDU
    """
    def __init__(self, roa, eot, payload):
        super(X224PDU, self).__init__(2, X224Header.X224_TPDU_DATA, payload)
        self.roa = roa
        self.eot = eot

class X224Error(X224PDU):
    """
    @summary: X224 Error PDU
    """
    def __init__(self, destination, cause):
        super(X224PDU, self).__init__(len(payload) + 4, X224Header.X224_TPDU_ERROR, payload)
        self.destination = destination
        self.cause = cause



class X224Parser:
    """
    @summary: Parser for X224 PDUs
    """

    def __init__(self):
        self.parsers = {
            X224Header.X224_TPDU_CONNECTION_REQUEST: self.parseConnectionRequest,
            X224Header.X224_TPDU_CONNECTION_CONFIRM: self.parseConnectionConfirm,
            X224Header.X224_TPDU_DISCONNECT_REQUEST: self.parseDisconnectRequest,
            X224Header.X224_TPDU_DATA: self.parseData,
            X224Header.X224_TPDU_ERROR: self.parseError,
        }

        self.writers = {
            X224Header.X224_TPDU_CONNECTION_REQUEST: self.writeConnectionRequest,
            X224Header.X224_TPDU_CONNECTION_CONFIRM: self.writeConnectionConfirm,
            X224Header.X224_TPDU_DISCONNECT_REQUEST: self.writeDisconnectRequest,
            X224Header.X224_TPDU_DATA: self.writeData,
            X224Header.X224_TPDU_ERROR: self.writeError,
        }

    def parse(self, data):
        length = Uint8.read(data[0])
        header = Uint8.read(data[1]) >> 4

        if length < 2 or len(steam) < length:
            raise Exception("Invalid X224 length indicator")

        if header not in self.parsers:
            raise Exception("Unknown X224 header received")
        
        return self.parsers[header](data, length)
    
    def parseConnectionPDU(self, data, length, name):
        if length < 6:
            raise Exception("Invalid %s" % name)
        
        destination = Uint16BE.read(data[2 : 4])
        source = Uint16BE.read(data[4 : 6])
        options = Uint8.read(data[6])
        payload = data[7 :]

        if length(payload) != length - 6:
            raise Exception("Invalid length indicator for X224 %s" % name)
        
        return source, destination, options, payload
    
    def parseConnectionRequest(self, data, length):
        credit = data[1] & 0xf
        destination, source, options, payload = self.parseConnectionPDU(data, length, "Connection Request")
        return X224ConnectionRequest(credit, destination, source, options, payload)
    
    def parseConnectionConfirm(self, data, length):
        credit = data[1] & 0xf
        destination, source, options, payload = self.parseConnectionPDU(data, length, "Connection Confirm")
        return X224ConnectionConfirm(credit, destination, source, options, payload)
    
    def parseDisconnectRequest(self, data, length):
        destination, source, reason, payload = self.parseConnectionPDU(data, length, "Disconnect Request")
        return X224DisconnectRequest(destination, source, reason, payload)
    
    def parseData(self, data, length):
        if length != 2:
            raise Exception("Invalid length indicator for X224 Data PDU")
        
        code = Uint8.read(data[1]) & 0xf
        sequence = Uint8.read(data[2])
        payload = data[3 :]
        
        return X224Data(code & 1 == 1, sequence & 0x80 == 0x80, payload)
    
    def parseError(self, data, length):
        if length < 4:
            raise Exception("Invalid X224 Error PDU")
        
        destination = Uint16BE.read(data[2 : 4])
        cause = Uint8.read(data[4])
        payload = data[5 :]

        if len(payload) != length - 4:
            raise Exception("Invalid length indicator for X224 Error PDU")
        
        return X224Error(destination, cause, payload)
        
    def write(self, pdu):
        stream = StringIO()
        stream.write(pdu.length)
        
        if pdu.header not in self.writers:
            raise Exception("Unknown X224 header")
        
        self.writers[pdu.header].write(stream, pdu)
        stream.write(pdu.payload)
        return stream.getvalue()
    
    def writeConnectionPDU(self, stream, header, destination, source, options):
        stream.write(Uint8.write(header))
        stream.write(Uint16BE.write(destination))
        stream.write(Uint16BE.write(source))
        stream.write(Uint8.write(options))
    
    def writeConnectionRequest(self, stream, pdu):
        header = (pdu.header << 4) | (pdu.credit & 0xf)
        self.writeConnectionPDU(stream, header, pdu.destination, pdu.source, pdu.options)
    
    def writeConnectionConfirm(self, stream, pdu):
        header = (pdu.header << 4) | (pdu.credit & 0xf)
        self.writeConnectionPDU(stream, header, pdu.destination, pdu.source, pdu.options)
    
    def writeDisconnectRequest(self, stream, pdu):
        self.writeConnectionPDU(stream, pdu.header, pdu.destination, pdu.source, pdu.reason)
    
    def writeData(self, stream, pdu):
        header = (pdu.header << 4) | int(pdu.roa)
        stream.write(header)
        stream.write(int(pdu.eot) << 8)
    
    def writeError(self, stream, pdu):
        stream.write(pdu.header)
        stream.write(pdu.destination)
        stream.write(pdu.cause)