from StringIO import StringIO

from rdpy.core import ber, per
from rdpy.core.error import InvalidValue, InvalidSize
from rdpy.core.packing import Uint8, Uint16BE


class MCSPDUType:
    """
    MCS PDU Headers
    """
    # Connection PDU headers
    CONNECT_INITIAL = 0x65
    CONNECT_RESPONSE = 0x66

    # Domain PDU headers
    ERECT_DOMAIN_REQUEST = 1
    DISCONNECT_PROVIDER_ULTIMATUM = 8
    ATTACH_USER_REQUEST = 10
    ATTACH_USER_CONFIRM = 11
    CHANNEL_JOIN_REQUEST = 14
    CHANNEL_JOIN_CONFIRM = 15
    SEND_DATA_REQUEST = 25
    SEND_DATA_INDICATION = 26

class MCSChannel:
    """
    Channel IDs of the main channels used in RDP
    """
    USERCHANNEL_BASE = 1001
    GLOBAL_CHANNEL = 1003
    RDPDR_CHANNEL = 1004  # Not handled by RDPY
    CLIPRDR_CHANNEL = 1005  # Not handled by RDPY
    RDPSND_CHANNEL = 1006  # Not handled by RDPY

class MCSResult:
    RT_SUCCESSFUL = 0x00

class MCSDomainParams:
    def __init__(self, maxChannelIDs, maxUserIDs, maxTokenIDs, numPriorities, minThroughput, maxHeight, maxMCSPDUSize, protocolVersion):
        self.maxChannelIDs = maxChannelIDs
        self.maxUserIDs = maxUserIDs
        self.maxTokenIDs = maxTokenIDs
        self.numPriorities = numPriorities
        self.minThroughput = minThroughput
        self.maxHeight = maxHeight
        self.maxMCSPDUSize = maxMCSPDUSize
        self.protocolVersion = protocolVersion
    
    @staticmethod
    def createTarget(maxChannelIDs, maxUserIDs):
        return MCSDomainParams(maxChannelIDs, maxUserIDs, 0, 1, 0, 1, 65535, 2)

    @staticmethod
    def createMinimum():
        return MCSDomainParams(1, 1, 1, 1, 0, 1, 1056, 2)

    @staticmethod
    def createMaximum():
        return MCSDomainParams(65535, 64535, 65535, 1, 0, 1, 65535, 2)


class MCSPDU(object):
    """
    Base class for MCS PDUs (not actually a PDU)
    """
    def __init__(self, type, payload):
        self.header = type
        self.payload = payload

class MCSConnectInitialPDU(MCSPDU):
    def __init__(self, callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload):
        super(MCSConnectInitialPDU, self).__init__(MCSPDUType.CONNECT_INITIAL, payload)
        self.callingDomain = callingDomain
        self.calledDomain = calledDomain
        self.upward = upward
        self.targetParams = targetParams
        self.minParams = minParams
        self.maxParams = maxParams

class MCSConnectResponsePDU(MCSPDU):
    def __init__(self, result, calledConnectID, domainParams, payload):
        super(MCSConnectResponsePDU, self).__init__(MCSPDUType.CONNECT_RESPONSE, payload)
        self.result = result
        self.calledConnectID = calledConnectID
        self.domainParams = domainParams

class MCSErectDomainRequestPDU(MCSPDU):
    def __init__(self, subHeight, subInterval, payload):
        super(MCSErectDomainRequestPDU, self).__init__(MCSPDUType.ERECT_DOMAIN_REQUEST, payload)
        self.subHeight = subHeight
        self.subInterval = subInterval

class MCSDisconnectProviderUltimatumPDU(MCSPDU):
    def __init__(self, reason):
        super(MCSDisconnectProviderUltimatumPDU, self).__init__(MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM, "")
        self.reason = reason

class MCSAttachUserRequestPDU(MCSPDU):
    def __init__(self):
        super(MCSAttachUserRequestPDU, self).__init__(MCSPDUType.ATTACH_USER_REQUEST, "")

class MCSAttachUserConfirmPDU(MCSPDU):
    def __init__(self, result, initiator = None):
        super(MCSAttachUserConfirmPDU, self).__init__(MCSPDUType.ATTACH_USER_CONFIRM, "")
        self.result = result
        self.initiator = initiator

class MCSChannelJoinRequestPDU(MCSPDU):
    def __init__(self, initiator, channelID, payload):
        super(MCSChannelJoinRequestPDU, self).__init__(MCSPDUType.CHANNEL_JOIN_REQUEST, payload)
        self.initiator = initiator
        self.channelID = channelID

class MCSChannelJoinConfirmPDU(MCSPDU):
    def __init__(self, result, initiator, requested, channelID, payload):
        super(MCSChannelJoinConfirmPDU, self).__init__(MCSPDUType.CHANNEL_JOIN_CONFIRM, payload)
        self.result = result
        self.initiator = initiator
        self.requested = requested
        self.channelID = channelID

class MCSSendDataRequestPDU(MCSPDU):
    def __init__(self, initiator, channelID, priority, payload):
        super(MCSSendDataRequestPDU, self).__init__(MCSPDUType.SEND_DATA_REQUEST, payload)
        self.initiator = initiator
        self.channelID = channelID
        self.priority = priority

class MCSSendDataIndicationPDU(MCSPDU):
    def __init__(self, initiator, channelID, priority, payload):
        super(MCSSendDataIndicationPDU, self).__init__(MCSPDUType.SEND_DATA_INDICATION, payload)
        self.initiator = initiator
        self.channelID = channelID
        self.priority = priority



class MCSParser:
    def __init__(self):
        self.parsers = {
            MCSPDUType.CONNECT_INITIAL: self.parseConnectInitial,
            MCSPDUType.CONNECT_RESPONSE: self.parseConnectResponse,
            MCSPDUType.ERECT_DOMAIN_REQUEST: self.parseErectDomainRequest,
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: self.parseDisconnectProviderUltimatum,
            MCSPDUType.ATTACH_USER_REQUEST: self.parseAttachUserRequest,
            MCSPDUType.ATTACH_USER_CONFIRM: self.parseAttachUserConfirm,
            MCSPDUType.CHANNEL_JOIN_REQUEST: self.parseChannelJoinRequest,
            MCSPDUType.CHANNEL_JOIN_CONFIRM: self.parseChannelJoinConfirm,
            MCSPDUType.SEND_DATA_REQUEST: self.parseSendDataRequest,
            MCSPDUType.SEND_DATA_INDICATION: self.parseSendDataIndication,
        }

        self.writers = {
            MCSPDUType.CONNECT_INITIAL: self.writeConnectInitial,
            MCSPDUType.CONNECT_RESPONSE: self.writeConnectResponse,
            MCSPDUType.ERECT_DOMAIN_REQUEST: self.writeErectDomainRequest,
            MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM: self.writeDisconnectProviderUltimatum,
            MCSPDUType.ATTACH_USER_REQUEST: self.writeAttachUserRequest,
            MCSPDUType.ATTACH_USER_CONFIRM: self.writeAttachUserConfirm,
            MCSPDUType.CHANNEL_JOIN_REQUEST: self.writeChannelJoinRequest,
            MCSPDUType.CHANNEL_JOIN_CONFIRM: self.writeChannelJoinConfirm,
            MCSPDUType.SEND_DATA_REQUEST: self.writeSendDataRequest,
            MCSPDUType.SEND_DATA_INDICATION: self.writeSendDataIndication,
        }

    def parse(self, data):
        """
        :param data: raw bytes to parse
        """
        stream = StringIO(data)
        header = Uint8.unpack(stream.read(1))
        if header == ber.Class.BER_CLASS_APPL | ber.BerPc.BER_CONSTRUCT | ber.Tag.BER_TAG_MASK:
            header = Uint8.unpack(stream.read(1))
        else:
            header = header >> 2
        
        if header not in self.parsers:
            raise Exception("Unhandled header received")
        
        return self.parsers[header](stream)

    def parseDomainParams(self, stream):
        """
        Parse a Domain Param from stream
        :param stream: stream containing the data
        """
        if not ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True):
            raise InvalidValue("Invalid BER tag (%d expected)" % ber.Tag.BER_TAG_SEQUENCE)
        
        length = ber.readLength(stream)
        if length > len(stream.getvalue()):
            raise InvalidSize("Invalid size for DomainParameters (got %d, %d bytes left)" % (length, len(stream.getvalue())))

        maxChannelIDs = ber.readInteger(stream)
        maxUserIDs = ber.readInteger(stream)
        maxTokenIDs = ber.readInteger(stream)
        numPriorities = ber.readInteger(stream)
        minThroughput = ber.readInteger(stream)
        maxHeight = ber.readInteger(stream)
        maxMCSPDUSize = ber.readInteger(stream)
        protocolVersion = ber.readInteger(stream)
        return MCSDomainParams(maxChannelIDs, maxUserIDs, maxTokenIDs, numPriorities, minThroughput, maxHeight, maxMCSPDUSize, protocolVersion)

    def parseConnectInitial(self, stream):
        """
        Parse a Connect Initial PDU
        :param stream: stream containing the data
        """
        length = ber.readLength(stream)
        callingDomain = ber.readOctetString(stream)
        calledDomain = ber.readOctetString(stream)
        upward = ber.readBoolean(stream)
        targetParams = self.parseDomainParams(stream)
        minParams = self.parseDomainParams(stream)
        maxParams = self.parseDomainParams(stream)
        payload = ber.readOctetString(stream)
        return MCSConnectInitialPDU(callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload)
    
    def parseConnectResponse(self, stream):
        """
        Parse a Connect Response PDU
        :param stream: stream containing the data
        """
        length = ber.readLength(stream)
        result = ber.readEnumerated(stream)
        calledConnectID = ber.readInteger(stream)
        domainParams = self.parseDomainParams(stream)
        payload = ber.readOctetString(stream)
        return MCSConnectResponsePDU(result, calledConnectID, domainParams, payload)
    
    def parseErectDomainRequest(self, stream):
        """
        Parse an Erect Domain Request PDU
        :param stream: stream containing the data
        """
        subHeight = per.readInteger(stream)
        subInterval = per.readInteger(stream)
        payload = stream.read()
        return MCSErectDomainRequestPDU(subHeight, subInterval, payload)
    
    def parseDisconnectProviderUltimatum(self, stream):
        """
        Parse a Disconnect Provider Ultimatum PDU
        :param stream: stream containing the data
        """
        reason = ber.readEnumeration(stream)

        if len(stream.read()) > 0:
            raise Exception("Unexpected payload")
        
        return MCSDisconnectProviderUltimatumPDU(reason)

    def parseAttachUserRequest(self, stream):
        """
        Parse an Attach User Request PDU
        :param stream: stream containing the data
        """
        if len(stream.read()) > 0:
            raise Exception("Unexpected payload")
        
        return MCSAttachUserRequestPDU()
    
    def parseAttachUserConfirm(self, stream):
        """
        Parse an Attach User Confirm PDU
        :param stream: stream containing the data
        """
        result = per.readEnumeration(stream)
        data = stream.read()

        if len(data) == 0:
            initiator = None
        elif len(data) == 2:
            initiator = Uint16BE.unpack(data) + MCSChannel.USERCHANNEL_BASE
        elif len(data) > 2:
            raise Exception("Unexpected payload")

        return MCSAttachUserConfirmPDU(result, initiator)
    
    def parseChannelJoinRequest(self, stream):
        """
        Parse a Channel Join Request PDU
        :param stream: stream containing the data
        """
        data = stream.read()
        if len(data) < 4:
            raise Exception("Invalid Channel Join Request PDU received")
        
        initiator = Uint16BE.unpack(data[0 : 2]) + MCSChannel.USERCHANNEL_BASE
        channelID = Uint16BE.unpack(data[2 : 4])
        payload = data[4 :]
        
        return MCSChannelJoinRequestPDU(initiator, channelID, payload)
    
    def parseChannelJoinConfirm(self, stream):
        """
        Parse a Channel Join Confirm PDU
        :param stream: stream containing the data
        """
        result = per.readEnumeration(stream)
        data = stream.read()

        if len(data) < 4 or len(data) == 5:
            raise Exception("Invalid Channel Join Confirm PDU received")
        elif len(data) >= 6:
            channelID = Uint16BE.unpack(data[4 : 6])
            payload = data[6 :]
        else:
            channelID = None
            payload = ""
    
        initiator = Uint16BE.unpack(data[0 : 2]) + MCSChannel.USERCHANNEL_BASE
        requested = Uint16BE.unpack(data[2 : 4])
        return MCSChannelJoinConfirmPDU(result, initiator, requested, channelID, payload)
    
    def parseDataPDU(self, stream, PDUClass):
        """
        Common logic for parsing Send Data Request and Send Data Indication PDUs
        :param stream: stream containing the data
        :param PDUClass: the actual PDU class
        """
        initiator = Uint16BE.unpack(stream.read(2)) + MCSChannel.USERCHANNEL_BASE
        channelID = Uint16BE.unpack(stream.read(2))
        priority = per.readEnumeration(stream)
        payload = per.readOctetStream(stream)
        return PDUClass(initiator, channelID, priority, payload)

    def parseSendDataRequest(self, stream):
        """
        Parse a Send Data Request PDU
        :param stream: stream containing the data
        """
        return self.parseDataPDU(stream, MCSSendDataRequestPDU)
    
    def parseSendDataIndication(self, stream):
        """
        Parse a Send Data Indication PDU
        :param stream: stream containing the data
        """
        return self.parseDataPDU(stream, MCSSendDataIndicationPDU)
    


    def write(self, pdu):
        """
        Encode an MCS PDU
        :param pdu: the PDU to encode
        """
        if pdu.header not in self.writers:
            raise Exception("Trying to send unhandled PDU type")

        stream = StringIO()
        
        if pdu.header in [MCSPDUType.CONNECT_INITIAL, MCSPDUType.CONNECT_RESPONSE]:
            stream.write(Uint8.pack(ber.Class.BER_CLASS_APPL | ber.BerPc.BER_CONSTRUCT | ber.Tag.BER_TAG_MASK))
            stream.write(Uint8.pack(pdu.header))
        else:
            stream.write(Uint8.pack(pdu.header << 2))

        self.writers[pdu.header](stream, pdu)
        return stream.getvalue()
        

    def writeDomainParams(self, stream, params):
        """
        Encode a Domain Params structure
        :param stream: the destination stream
        :param params: the domain params
        """
        substream = StringIO()
        substream.write(ber.writeInteger(params.maxChannelIDs))
        substream.write(ber.writeInteger(params.maxUserIDs))
        substream.write(ber.writeInteger(params.maxTokenIDs))
        substream.write(ber.writeInteger(params.numPriorities))
        substream.write(ber.writeInteger(params.minThroughput))
        substream.write(ber.writeInteger(params.maxHeight))
        substream.write(ber.writeInteger(params.maxMCSPDUSize))
        substream.write(ber.writeInteger(params.protocolVersion))

        substream = substream.getvalue()
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(len(substream)))
        stream.write(substream)
    
    def writeConnectInitial(self, stream, pdu):
        """
        Encode a Connect Initial PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        substream = StringIO()
        substream.write(ber.writeOctetString(pdu.callingDomain))
        substream.write(ber.writeOctetString(pdu.calledDomain))
        substream.write(ber.writeBoolean(pdu.upward))
        self.writeDomainParams(substream, pdu.targetParams)
        self.writeDomainParams(substream, pdu.minParams)
        self.writeDomainParams(substream, pdu.maxParams)
        substream.write(ber.writeOctetString(pdu.payload))
        
        data = substream.getvalue()
        stream.write(ber.writeLength(len(data)))
        stream.write(data)
    
    def writeConnectResponse(self, stream, pdu):
        """
        Encode a Connect Response PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        substream = StringIO()
        substream.write(ber.writeEnumerated(pdu.result))
        substream.write(ber.writeInteger(pdu.calledConnectID))
        self.writeDomainParams(substream, pdu.domainParams)
        substream.write(ber.writeOctetString(pdu.payload))
        allData = substream.getvalue()
        stream.write(ber.writeLength(len(allData)))
        stream.write(allData)
    
    def writeErectDomainRequest(self, stream, pdu):
        """
        Encode an Erect Domain Request PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        stream.write(per.writeInteger(pdu.subHeight))
        stream.write(per.writeInteger(pdu.subInterval))
        stream.write(pdu.payload)
    
    def writeDisconnectProviderUltimatum(self, stream, pdu):
        """
        Encode a Disconnect Provider Ultimatum PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        stream.write(per.writeEnumerated(pdu.reason))
    
    def writeAttachUserRequest(self, stream, pdu):
        """
        Encode an Attach User Request PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        pass
    
    def writeAttachUserConfirm(self, stream, pdu):
        """
        Encode an Attach User Confirm PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        stream.write(per.writeEnumeration(pdu.result))

        if pdu.initiator is not None:
            stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
    
    def writeChannelJoinRequest(self, stream, pdu):
        """
        Encode a Channel Join Request PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.channelID))
        stream.write(pdu.payload)
    
    def writeChannelJoinConfirm(self, stream, pdu):
        """
        Encode a Channel Join Confirm PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        stream.write(per.writeEnumeration(pdu.result))
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.requested))

        if pdu.channelID is not None:
            stream.write(Uint16BE.pack(pdu.channelID))
            stream.write(pdu.payload)
    
    def writeDataPDU(self, stream, pdu):
        """
        Base logic for encoding Send Data Request and Send Data Indication PDUs
        :param stream: the destination stream
        :param pdu: the PDU
        """
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.channelID))
        stream.write(per.writeEnumeration(pdu.priority))
        stream.write(per.writeOctetStream(pdu.payload))
    
    def writeSendDataRequest(self, stream, pdu):
        """
        Encode a Send Data Request PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        self.writeDataPDU(stream, pdu)
    
    def writeSendDataIndication(self, stream, pdu):
        """
        Encode a Send Data Indication PDU
        :param stream: the destination stream
        :param pdu: the PDU
        """
        self.writeDataPDU(stream, pdu)