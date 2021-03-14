#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

class PyRDPError(Exception):
    """Base class for PyRDP errors"""


class ParsingError(PyRDPError, ValueError):
    def __init__(self, *args):
        super().__init__(*args)
        self.layers = []

    """A parser tried to parse a malformed PDU"""
    def addLayer(self, parser: object, data: bytes):
        self.layers.insert(0, (type(parser).__name__, data))

    def formatLayer(self, index: int) -> str:
        layer = self.layers[index]
        return f"{layer[0]} = {layer[1].hex()}"

    def formatLayers(self) -> str:
        return ",".join(self.formatLayer(i) for i in range(len(self.layers)))


class ExploitError(ParsingError):
    """
    Class used when an exploit attempt or scan is detected in a parser and we want to shut down the connection.
    """

    def __init__(self, *args):
        super().__init__(*args)


class WritingError(PyRDPError, ValueError):
    """A parser tried to write a malformed PDU"""


class UnknownPDUTypeError(PyRDPError, NotImplementedError):
    """A parser tried to write or parse an unknown PDU type"""

    def __init__(self, message, type):
        super(UnknownPDUTypeError, self).__init__(message)
        self.type = type


class StateError(PyRDPError, RuntimeError):
    """Used when trying to do something that an object's state does not allow"""


class CrypterUnavailableError(PyRDPError):
    """Used when trying to use a CrypterProxy before the actual crypter was generated"""
