"""
File that contains helper methods to use in the library.
"""


def decodeUTF16LE(data: bytes) -> str:
    """
    Decode the provided bytes in UTF-16 in a way that does not crash when invalid input is provided.
    :param data: The data to decode as utf-16.
    :return: The python string
    """
    return data.decode("utf-16le", errors="surrogateescape").strip("\x00")
