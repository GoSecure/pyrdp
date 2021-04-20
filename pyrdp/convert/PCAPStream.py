class PCAPStream:
    def __init__(self, client: str, server: str):
        self.client = client
        self.server = server

    @property
    def ips(self):
        return [self.client, self.server]

    def __len__(self):
        raise NotImplementedError("PCAPStream.__len__ is not implemented.")

    def __iter__(self):
        raise NotImplementedError("PCAPStream.__iter__ is not implemented.")

    @staticmethod
    def timeStampFloatToInt(timeStamp: float):
        return int(timeStamp * 1000)

    @staticmethod
    def output(data: bytes, timeStamp: float, srcIp: str, dstIp: str):
        return data, PCAPStream.timeStampFloatToInt(timeStamp), srcIp, dstIp
