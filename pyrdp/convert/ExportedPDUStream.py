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

    def __len__(self):
        return len(self.packets)

    def __iter__(self):
        return self.parsePDUs()

    def parsePDUs(self):
        """
        Generator function that parses Exported PDUs from Wireshark and outputs them.
        """

        n = 0

        while True:
            if n >= len(self):
                raise StopIteration

            packet = self.packets[n]
            src = ".".join(str(b) for b in packet.load[12:16])
            dst = ".".join(str(b) for b in packet.load[20:24])
            data = packet.load[60:]
            n += 1

            if any(ip not in self.ips for ip in [src, dst]):
                continue

            yield PCAPStream.output(data, packet.time, src, dst)
