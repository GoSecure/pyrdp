from StringIO import StringIO
from collections import defaultdict

from rdpy.core import ber, per
from rdpy.core.error import InvalidValue, InvalidSize
from rdpy.core.packing import Uint8, Uint16BE
from rdpy.enum.mcs import MCSChannelID, MCSPDUType
from rdpy.exceptions import UnknownPDUTypeError, ParsingError
from rdpy.pdu.mcs import MCSConnectInitialPDU, MCSConnectResponsePDU, MCSErectDomainRequestPDU, \
    MCSDisconnectProviderUltimatumPDU, MCSAttachUserRequestPDU, MCSAttachUserConfirmPDU, MCSChannelJoinRequestPDU, \
    MCSChannelJoinConfirmPDU, MCSSendDataRequestPDU, MCSSendDataIndicationPDU, MCSDomainParams


class MCSParser:
    """
    Parser class to read and write MCS (T.125) PDUs.
    """

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

        self.headerOptions = defaultdict(int)
        self.headerOptions[MCSPDUType.DISCONNECT_PROVIDER_ULTIMATUM] = 1
        self.headerOptions[MCSPDUType.ATTACH_USER_CONFIRM] = 2
        self.headerOptions[MCSPDUType.CHANNEL_JOIN_CONFIRM] = 2

    def parse(self, data):
        """
        Parse raw data bytes into a MCSPDU
        :param data: raw bytes to parse
        :type data: str
        :return: MCSPDU
        """

        stream = StringIO(data)
        header = Uint8.unpack(stream.read(1))
        if header == ber.Class.BER_CLASS_APPL | ber.PC.BER_CONSTRUCT | ber.Tag.BER_TAG_MASK:
            header = Uint8.unpack(stream.read(1))
        else:
            header = header >> 2

        if header not in self.parsers:
            raise UnknownPDUTypeError("Trying to parse unknown MCS PDU type %s" % header, header)

        return self.parsers[header](stream)

    def parseDomainParams(self, stream):
        """
        Parse a MCSDomainParam from stream
        :param stream: byte stream containing the data
        :type stream: StringIO
        :return: MCSDomainParam
        """
        if not ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True):
            raise ParsingError("Invalid BER tag (%d expected)" % ber.Tag.BER_TAG_SEQUENCE)

        length = ber.readLength(stream)
        if length > len(stream.getvalue()):
            raise ParsingError("Invalid size for DomainParameters (got %d, %d bytes left)" % (length, len(stream.getvalue())))

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
        :type stream: StringIO
        :return: MCSConnectInitialPDU
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
        :type stream: StringIO
        :return: MCSConnectResponsePDU
        """
        length = ber.readLength(stream)
        result = ber.readEnumeration(stream)
        calledConnectID = ber.readInteger(stream)
        domainParams = self.parseDomainParams(stream)
        payload = ber.readOctetString(stream)
        return MCSConnectResponsePDU(result, calledConnectID, domainParams, payload)

    def parseErectDomainRequest(self, stream):
        """
        Parse an Erect Domain Request PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSErectDomainRequestPDU
        """
        subHeight = 1
        subInterval = 1

        try:
            # Windows generally does not seem to care about invalid erect domain requests, so use default values if
            # parsing fails.
            subHeight = per.readInteger(stream)
            subInterval = per.readInteger(stream)
        except InvalidValue:
            pass

        payload = stream.read()
        return MCSErectDomainRequestPDU(subHeight, subInterval, payload)

    def parseDisconnectProviderUltimatum(self, stream):
        """
        Parse a Disconnect Provider Ultimatum PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSDisconnectProviderUltimatumPDU
        """
        reason = per.readEnumeration(stream)

        if len(stream.read()) > 0:
            raise ParsingError("Unexpected payload")

        return MCSDisconnectProviderUltimatumPDU(reason)

    def parseAttachUserRequest(self, stream):
        """
        Parse an Attach User Request PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSAttachUserRequestPDU
        """
        if len(stream.read()) > 0:
            raise ParsingError("Unexpected payload")

        return MCSAttachUserRequestPDU()

    def parseAttachUserConfirm(self, stream):
        """
        Parse an Attach User Confirm PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSAttachUserConfirmPDU
        """
        result = per.readEnumeration(stream)
        data = stream.read()

        initiator = None
        if len(data) == 2:
            initiator = Uint16BE.unpack(data) + MCSChannelID.USERCHANNEL_BASE
        elif len(data) > 2:
            raise ParsingError("Unexpected payload")

        return MCSAttachUserConfirmPDU(result, initiator)

    def parseChannelJoinRequest(self, stream):
        """
        Parse a Channel Join Request PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSChannelJoinRequestPDU
        """
        data = stream.read()
        if len(data) < 4:
            raise ParsingError("Invalid Channel Join Request PDU received")

        initiator = Uint16BE.unpack(data[0 : 2]) + MCSChannelID.USERCHANNEL_BASE
        channelID = Uint16BE.unpack(data[2 : 4])
        payload = data[4 :]

        return MCSChannelJoinRequestPDU(initiator, channelID, payload)

    def parseChannelJoinConfirm(self, stream):
        """
        Parse a Channel Join Confirm PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSChannelJoinConfirmPDU
        """
        result = per.readEnumeration(stream)
        data = stream.read()

        if len(data) < 4 or len(data) == 5:
            raise ParsingError("Invalid Channel Join Confirm PDU received")
        elif len(data) >= 6:
            channelID = Uint16BE.unpack(data[4 : 6])
            payload = data[6 :]
        else:
            channelID = None
            payload = ""

        initiator = Uint16BE.unpack(data[0 : 2]) + MCSChannelID.USERCHANNEL_BASE
        requested = Uint16BE.unpack(data[2 : 4])
        return MCSChannelJoinConfirmPDU(result, initiator, requested, channelID, payload)

    def parseDataPDU(self, stream, PDUClass):
        """
        Common logic for parsing Send Data Request and Send Data Indication PDUs
        :param stream: stream containing the data
        :type stream: StringIO
        :param PDUClass: the actual PDU class: MCSSendDataRequestPDU|MCSSendDataIndicationPDU
        :return: MCSSendDataRequestPDU|MCSSendDataIndicationPDU
        """
        initiator = Uint16BE.unpack(stream.read(2)) + MCSChannelID.USERCHANNEL_BASE
        channelID = Uint16BE.unpack(stream.read(2))
        priority = per.readEnumeration(stream)
        payload = per.readOctetStream(stream)
        return PDUClass(initiator, channelID, priority, payload)

    def parseSendDataRequest(self, stream):
        """
        Parse a Send Data Request PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSSendDataRequestPDU
        """
        return self.parseDataPDU(stream, MCSSendDataRequestPDU)

    def parseSendDataIndication(self, stream):
        """
        Parse a Send Data Indication PDU
        :param stream: stream containing the data
        :type stream: StringIO
        :return: MCSSendDataIndicationPDU
        """
        return self.parseDataPDU(stream, MCSSendDataIndicationPDU)

    def write(self, pdu):
        """
        Encode an MCS PDU into raw bytes
        :param pdu: the MCSPDU to encode
        :type pdu: rdpy.pdu.mcs.MCSPDU
        :return: str The raw bytes to send
        """
        if pdu.header not in self.writers:
            raise UnknownPDUTypeError("Trying to write unknown MCS PDU type %s" % pdu.header, pdu.header)

        stream = StringIO()

        if pdu.header in [MCSPDUType.CONNECT_INITIAL, MCSPDUType.CONNECT_RESPONSE]:
            stream.write(Uint8.pack(ber.Class.BER_CLASS_APPL | ber.PC.BER_CONSTRUCT | ber.Tag.BER_TAG_MASK))
            stream.write(Uint8.pack(pdu.header))
        else:
            stream.write(Uint8.pack((pdu.header << 2) | self.headerOptions[pdu.header]))

        self.writers[pdu.header](stream, pdu)
        return stream.getvalue()

    def writeDomainParams(self, stream, params):
        """
        Encode a Domain Params structure into the provided stream
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type params: MCSDomainParams
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
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSConnectInitialPDU
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
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSConnectResponsePDU
        """
        substream = StringIO()
        substream.write(ber.writeEnumeration(pdu.result))
        substream.write(ber.writeInteger(pdu.calledConnectID))
        self.writeDomainParams(substream, pdu.domainParams)
        substream.write(ber.writeOctetString(pdu.payload))
        allData = substream.getvalue()
        stream.write(ber.writeLength(len(allData)))
        stream.write(allData)

    def writeErectDomainRequest(self, stream, pdu):
        """
        Encode a Erect Domain Request PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSErectDomainRequestPDU
        """
        stream.write(per.writeInteger(pdu.subHeight))
        stream.write(per.writeInteger(pdu.subInterval))
        stream.write(pdu.payload)

    def writeDisconnectProviderUltimatum(self, stream, pdu):
        """
        Encode a Disconnect Provider Ultimatum PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSDisconnectProviderUltimatumPDU
        """
        stream.write(per.writeEnumeration(pdu.reason))

    def writeAttachUserRequest(self, stream, pdu):
        """
        Does nothing :)
        """
        pass

    def writeAttachUserConfirm(self, stream, pdu):
        """
        Encode a Attach User Confirm PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSAttachUserConfirmPDU
        """
        stream.write(per.writeEnumeration(pdu.result))

        if pdu.initiator is not None:
            stream.write(Uint16BE.pack(pdu.initiator - MCSChannelID.USERCHANNEL_BASE))

    def writeChannelJoinRequest(self, stream, pdu):
        """
        Encode a Channel Join Request PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSChannelJoinRequestPDU
        """
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannelID.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.channelID))
        stream.write(pdu.payload)

    def writeChannelJoinConfirm(self, stream, pdu):
        """
        Encode a Channel Join Confirm PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSChannelJoinConfirmPDU
        """
        stream.write(per.writeEnumeration(pdu.result))
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannelID.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.requested))

        if pdu.channelID is not None:
            stream.write(Uint16BE.pack(pdu.channelID))
            stream.write(pdu.payload)

    def writeDataPDU(self, stream, pdu):
        """
        Encode a Data PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSSendDataIndicationPDU|MCSSendDataRequestPDU
        """
        stream.write(Uint16BE.pack(pdu.initiator - MCSChannelID.USERCHANNEL_BASE))
        stream.write(Uint16BE.pack(pdu.channelID))
        stream.write(per.writeEnumeration(pdu.priority))
        stream.write(per.writeOctetStream(pdu.payload))

    def writeSendDataRequest(self, stream, pdu):
        """
        Encode a Send Data Request PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSSendDataRequestPDU
        """
        self.writeDataPDU(stream, pdu)

    def writeSendDataIndication(self, stream, pdu):
        """
        Encode a Send Data Indication PDU
        :param stream: The destination stream to write into.
        :type stream: StringIO
        :type pdu: MCSSendDataIndicationPDU
        """
        self.writeDataPDU(stream, pdu)
