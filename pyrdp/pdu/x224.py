#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.enum import X224PDUType
from pyrdp.pdu.pdu import PDU


class X224PDU(PDU):
    """
    X.224 (T.125) PDU base class.
    """

    def __init__(self, header: X224PDUType, payload: bytes):
        """
        :param header: The PDU type.
        """

        super().__init__(payload)
        self.header = header


class X224ConnectionRequestPDU(X224PDU):

    def __init__(self, credit: int, destination: int, source: int, options: int, payload: bytes):
        super().__init__(X224PDUType.X224_TPDU_CONNECTION_REQUEST, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options


class X224ConnectionConfirmPDU(X224PDU):

    def __init__(self, credit: int, destination: int, source: int, options: int, payload: bytes):
        super().__init__(X224PDUType.X224_TPDU_CONNECTION_CONFIRM, payload)
        self.credit = credit
        self.destination = destination
        self.source = source
        self.options = options


class X224DisconnectRequestPDU(X224PDU):

    def __init__(self, destination: int, source: int, reason: int, payload: bytes):
        super().__init__(X224PDUType.X224_TPDU_DISCONNECT_REQUEST, payload)
        self.destination = destination
        self.source = source
        self.reason = reason


class X224DataPDU(X224PDU):

    def __init__(self, roa: bool, eot: bool, payload: bytes):
        """
        :param roa: request of acknowledgement (this is False unless agreed upon during connection).
        :param eot: end of transmission (True if this is the last packet in a sequence).
        :param payload: the data bytes.
        """
        super().__init__(X224PDUType.X224_TPDU_DATA, payload)
        self.roa = roa
        self.eot = eot


class X224ErrorPDU(X224PDU):

    def __init__(self, destination: int, cause: int, payload: bytes = b""):
        super().__init__(X224PDUType.X224_TPDU_ERROR, payload)
        self.destination = destination
        self.cause = cause
