from StringIO import StringIO

from rdpy.core.packing import Uint16LE, Uint32LE

class RDPSecurityFlags:
    SEC_EXCHANGE_PKT = 0x0001
    SEC_TRANSPORT_REQ = 0x0002
    SEC_TRANSPORT_RSP = 0x0004
    SEC_ENCRYPT = 0x0008
    SEC_RESET_SEQNO = 0x0010
    SEC_IGNORE_SEQNO = 0x0020
    SEC_INFO_PKT = 0x0040
    SEC_LICENSE_PKT = 0x0080
    SEC_LICENSE_ENCRYPT_CS = 0x0100
    SEC_LICENSE_ENCRYPT_SC = 0x0200
    SEC_REDIRECTION_PKT = 0x0400
    SEC_SECURE_CHECKSUM = 0x0800
    SEC_AUTODETECT_REQ = 0x1000
    SEC_AUTODETECT_RSP = 0x2000
    SEC_HEARTBEAT = 0x4000
    SEC_FLAGSHI_VALID = 0x8000

class RDPSecurityExchangePDU:
    def __init__(self, header, clientRandom):
        self.header = header
        self.clientRandom = clientRandom

class RDPSecurityParser:
    def __init__(self):
        pass
    
    def parse(self, data):
        stream = StringIO(data)
        flags = Uint16LE.unpack(stream)

        if flags & RDPSecurityFlags.SEC_EXCHANGE_PKT == 0:
            raise Exception("Invalid header for Security Exchange PDU")
        
        if flags & RDPSecurityFlags.SEC_LICENSE_ENCRYPT_SC == 0:
            raise Exception("Expected SEC_LICENSE_ENCRYPT_SC flag (0x0200)")
        
        hiFlags = Uint16LE.unpack(stream)
        flags = (hiFlags << 16) | flags
        length = Uint32LE.unpack(stream)
        clientRandom = stream.read(length)
        return RDPSecurityExchangePDU(flags, clientRandom)
    
    def write(self, pdu):
        if pdu.header & RDPSecurityFlags.SEC_EXCHANGE_PKT == 0:
            raise Exception("Unknown Security PDU header")
        
        return Uint16LE.pack(pdu.header & 0xffff) + Uint16LE.pack(pdu.header >> 16) + Uint32LE.pack(len(pdu.clientRandom)) + pdu.clientRandom