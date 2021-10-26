#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.convert.PCAPStream import PCAPStream
from pyrdp.convert.pyrdp_scapy import *


class ExportedPDUStream(PCAPStream):
    """
    PDU stream for converting sessions that contain Wireshark Exported PDU.
    """

    def __init__(self, client: str, server: str, packets: PacketList):
        super().__init__(client, server)
        self.packets = packets
        self.n = 0

    def __len__(self):
        return len(self.packets)

    def __iter__(self):
        return self

    def __next__(self):

        while True:
            if self.n >= len(self):
                raise StopIteration

            packet = self.packets[self.n]
            src = ".".join(str(b) for b in packet.load[12:16])
            dst = ".".join(str(b) for b in packet.load[20:24])
            data = packet.load[60:]
            self.n += 1

            if any(ip not in self.ips for ip in [src, dst]):
                continue  # Skip packets not meant for this stream.

            return PCAPStream.output(data, packet.time, src, dst)
