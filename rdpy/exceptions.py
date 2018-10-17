class RDPYError(Exception):
    """Base class for RDPY errors"""

class ParsingError(RDPYError, ValueError):
    """A parser tried to parse a malformed PDU"""

class WritingError(RDPYError, ValueError):
    """A parser tried to write a malformed PDU"""

class UnknownPDUTypeError(RDPYError, NotImplementedError):
    """A parser tried to write or parse an unknown PDU type"""