class StrictStream:
    """
    Stream wrapper class that throws an EOFError when it reads fewer bytes than required.
    """
    def __init__(self, stream):
        """
        :param stream: the wrapped stream
        """
        self.stream = stream
    
    def read(self, length):
        """
        :param length: the amount of bytes to read
        :return: the data read
        :raises EOFError: when not enough data was read
        """
        data = self.stream.read(length)

        if len(data) != length:
            raise EOFError("Expected to read %d bytes, got %d bytes instead" % (length, len(data)))
        
        return data