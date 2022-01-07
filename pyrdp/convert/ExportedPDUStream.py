#
# This file is part of the PyRDP project.
# Copyright (C) 2021, 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pyrdp.convert.PCAPStream import PCAPStream
from pyrdp.convert.pyrdp_scapy import *
from pyrdp.convert.utils import extractInetAddressesFromPDUPacket, InetAddress


class ExportedPDUStream(PCAPStream):
    """
    PDU stream for converting sessions that contain Wireshark Exported PDU.
    """

    def __init__(self, client: InetAddress, server: InetAddress, packets: PacketList):
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
            src, dst = extractInetAddressesFromPDUPacket(packet)
            data = packet.load[60:]
            self.n += 1

            return PCAPStream.output(data, packet.time, src, dst)
