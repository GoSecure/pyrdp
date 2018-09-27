from StringIO import StringIO

from rdpy.core import ber, per
from rdpy.core.packing import Uint8, Uint16BE
from rdpy.core.error import InvalidExpectedDataException, InvalidValue, InvalidSize, CallPureVirtualFuntion

class MCSPDUType:
    """
    @summary: MCS PDU Headers
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
    @summary: Channel id of main channels use in RDP
    """
    USERCHANNEL_BASE = 1001
    GLOBAL_CHANNEL = 1003
    RDPDR_CHANNEL = 1004  # Not handled by RDPY
    CLIPRDR_CHANNEL = 1005  # Not handled by RDPY
    RDPSND_CHANNEL = 1006  # Not handled by RDPY

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



class MCSPDU:
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
        self.result = result,
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
        stream = StringIO(data)
        header = stream.read(1)
        if header == Class.BER_CLASS_APPL | BerPc.BER_CONSTRUCT | Tag.BER_TAG_MASK:
            header = stream.read(1)
        
        if header not in self.parsers:
            raise Exception("Unhandled header received")
        
        return self.parsers[header](stream)

    def parseDomainParams(self, stream):
        if not ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True):
            raise InvalidValue("Invalid BER tag (%d expected)" % ber.Tag.BER_TAG_SEQUENCE)
        
        length = ber.readLength(stream)
        if length != 0x19:
            raise InvalidSize("Invalid size for DomainParameters (%d expected, got %d)" % (0x19, length))

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
        callingDomain = ber.readOctetString(stream)
        calledDomain = ber.readOctetString(stream)
        upward = ber.readBoolean(stream)
        targetParams = self.parseDomainParams(stream)
        minParams = self.parseDomainParams(stream)
        maxParams = self.parseDomainParams(stream)
        payload = stream.read()
        return MCSConnectInitialPDU(callingDomain, calledDomain, upward, targetParams, minParams, maxParams, payload)
    
    def parseConnectResponse(self, stream):
        result = ber.readEnumerated(stream)
        calledConnectID = ber.readInteger(stream)
        domainParams = self.parseDomainParams(stream)
        payload = stream.read()
        return MCSConnectResponsePDU(result, calledConnectID, domainParams, payload)
    
    def parseErectDomainRequest(self, stream):
        subHeight = ber.readInteger(stream)
        subInterval = ber.readInteger(stream)
        payload = stream.read()
        return MCSErectDomainRequestPDU(subHeight, subInterval, payload)
    
    def parseDisconnectProviderUltimatum(self, stream):
        reason = ber.readEnumeration(stream)

        if len(stream.read()) > 0:
            raise Exception("Unexpected payload")
        
        return MCSDisconnectProviderUltimatumPDU(reason)

    def parseAttachUserRequest(self, stream):
        if len(stream.read()) > 0:
            raise Exception("Unexpected payload")
        
        return MCSAttachUserRequestPDU()
    
    def parseAttachUserConfirm(self, stream):
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
        data = stream.read()
        if len(data) < 4:
            raise Exception("Invalid Channel Join Request PDU received")
        
        initiator = Uint16BE.unpack(data[0 : 2]) + MCSChannel.USERCHANNEL_BASE
        channelID = Uint16BE.unpack(data[2 : 4])
        payload = data[4 :]
        
        return MCSChannelJoinRequestPDU(initiator, channelID, payload)
    
    def parseChannelJoinConfirm(self, stream):
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
    
    def parseDataPDU(self, stream, factory):
        initiator = Uint16BE.unpack(stream.read(2)) + MCSChannel.USERCHANNEL_BASE
        channelID = Uint16BE.unpack(stream.read(2))
        priority = per.readEnumeration(stream)
        payload = per.readOctetStream(stream)
        return factory(initiator, channelID, priority, payload)

    def parseSendDataRequest(self, stream):
        return parseDataPDU(stream, MCSSendDataRequestPDU)
    
    def parseSendDataIndication(self, stream):
        return parseDataPDU(stream, MCSSendDataIndicationPDU)
    


    def write(self, pdu):
        if pdu.header not in self.writers:
            raise Exception("Trying to send unhandled PDU type")

        stream = StringIO()
        
        if pdu.header in [MCSPDUType.CONNECT_INITIAL, MCSPDUType.CONNECT_RESPONSE]:
            stream.write(Uint8.pack(Class.BER_CLASS_APPL | BerPc.BER_CONSTRUCT | Tag.BER_TAG_MASK))
        
        stream.write(pdu.header)
        self.writers[pdu.header](stream, pdu)
        

    def writeDomainParams(self, stream, params):
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(0x19))
        stream.write(ber.writeInteger(params.maxChannelIDs))
        stream.write(ber.writeInteger(params.maxUserIDs))
        stream.write(ber.writeInteger(params.maxTokenIDs))
        stream.write(ber.writeInteger(params.numPriorities))
        stream.write(ber.writeInteger(params.minThroughput))
        stream.write(ber.writeInteger(params.maxHeight))
        stream.write(ber.writeInteger(params.maxMCSPDUSize))
        stream.write(ber.writeInteger(params.protocolVersion))
    
    def writeConnectInitial(self, stream, pdu):
        stream.write(ber.writeOctetString(pdu.callingDomain))
        stream.write(ber.writeOctetString(pdu.calledDomain))
        stream.write(ber.writeBoolean(pdu.upward))
        self.writeDomainParams(stream, pdu.targetParams)
        self.writeDomainParams(stream, pdu.minParams)
        self.writeDomainParams(stream, pdu.maxParams)
        stream.write(pdu.payload)
    
    def writeConnectResponse(self, stream, pdu):
        stream.write(ber.writeEnumerated(pdu.result))
        stream.write(ber.writeInteger(pdu.calledConnectID))
        self.writeDomainParams(pdu.domainParams)
        stream.write(pdu.payload)
    
    def writeErectDomainRequest(self, stream, pdu):
        stream.write(ber.writeInteger(pdu.subHeight))
        stream.write(ber.readInteger(pdu.subInterval))
        stream.write(pdu.payload)
    
    def writeDisconnectProviderUltimatum(self, stream, pdu):
        stream.write(per.writeEnumerated(pdu.reason))
    
    def writeAttachUserRequest(self, stream, pdu):
        pass
    
    def writeAttachUserConfirm(self, stream, pdu):
        stream.write(per.writeEnumeration(pdu.result))

        if pdu.initiator is not None:
            stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
    
    def writeChannelJoinRequest(self, stream, pdu):
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.channelID))
        stream.write(pdu.payload)
    
    def writeChannelJoinConfirm(self, stream, pdu):
        stream.write(per.writeEnumeration(pdu.result))
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.requested))

        if pdu.channelID is not None:
            stream.write(Uint16BE.pack(pdu.channelID))
            stream.write(pdu.payload)
    
    def writeDataPDU(self, stream, pdu):
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannel.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.channelID))
        stream.write(per.writeEnumeration(pdu.priority))
        stream.write(per.writeOctetStream(pdu.payload))
    
    def writeSendDataRequest(self, stream, pdu):
        self.writeDataPDU(stream, pdu)
    
    def writeSendDataIndication(self, stream, pdu):
        self.writeDataPDU(stream, pdu)