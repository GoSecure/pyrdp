#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.convert.utils import InetAddress


class PCAPStream:
    def __init__(self, client: InetAddress, server: InetAddress):
        self.client = client
        self.server = server

    @property
    def ips(self):
        return [self.client.ip, self.server.ip]

    def __len__(self):
        raise NotImplementedError("PCAPStream.__len__ is not implemented.")

    def __iter__(self):
        raise NotImplementedError("PCAPStream.__iter__ is not implemented.")

    @staticmethod
    def timeStampFloatToInt(timeStamp: float):
        return int(timeStamp * 1000)

    @staticmethod
    def output(data: bytes, timeStamp: float, src: InetAddress, dst: InetAddress):
        return data, PCAPStream.timeStampFloatToInt(timeStamp), src, dst
