from io import BytesIO


class ByteStream(BytesIO):
    """
    Stream used to read bytes.
    """


class StrictStream:
    """
    Stream wrapper class that throws an EOFError when it reads fewer bytes than required.
    """
    def __init__(self, stream: BytesIO):
        self.stream = stream

    def read(self, length: int):
        """
        Read data from the stream and raise an EOFError if not enough bytes were read.
        :param length: the amount of bytes to read.
        :raises EOFError: when not enough data was read.
        """
        data = self.stream.read(length)

        if len(data) != length:
            raise EOFError("Expected to read %d bytes, got %d bytes instead" % (length, len(data)))

        return data