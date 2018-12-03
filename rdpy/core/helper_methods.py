"""
File that contains helper methods to use in the library.
"""


def decodeUTF16LE(data: bytes) -> str:
    """
    Decode the provided bytes in UTF-16 in a way that does not crash when invalid input is provided.
    :param data: The data to decode as utf-16.
    :return: The python string
    """
    return data.decode("utf-16le", errors="ignore")


def encodeUTF16LE(string: str) -> bytes:
    """
    Encode the provided string in UTF-16 in a way that does not crash when invalid input is provided.
    :param string: The python string to encode to bytes
    :return: The raw bytes
    """
    return string.encode("utf-16le", errors="ignore")
