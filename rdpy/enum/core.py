from enum import IntEnum


class ParserMode(IntEnum):
    """
    Mode used by some parsers (Client or Server).
    """
    CLIENT = 0
    SERVER = 1