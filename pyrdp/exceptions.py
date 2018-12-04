class PyRDPError(Exception):
    """Base class for PyRDP errors"""


class ParsingError(PyRDPError, ValueError):
    """A parser tried to parse a malformed PDU"""


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
