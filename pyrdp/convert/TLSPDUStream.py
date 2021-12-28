#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from scapy.layers.inet import TCP, IP
from scapy.layers.tls.crypto.pkcs1 import pkcs_i2osp
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSNewSessionTicket
from scapy.layers.tls.record import TLSApplicationData, TLS
from scapy.layers.tls.session import tlsSession
from scapy.plist import PacketList

from pyrdp.convert.PCAPStream import PCAPStream
from pyrdp.convert.utils import InetAddress, TCPFlags
from pyrdp.parser import TPKTParser


class TLSPDUStream(PCAPStream):
    """
    PDU stream for converting sessions that use TLS.
    """

    def __init__(self, client: str, server: str, packets: PacketList, masterSecret: str):
        """
        The session must have been obtained using by calling bind_layers(TCP, TLS) and then sniff(..., session=TCPSession).
        This connects the TCP and TLS layers and allows Scapy to reconstruct the TCP stream.
        """

        super().__init__(client, server)
        self.packets = packets
        self.masterSecret = masterSecret

    def __len__(self):
        return len(self.packets)

    def __iter__(self):
        return self.decryptTLSStream()

    def decryptTLSStream(self):
        """
        Generator function that decrypts an RDP stream that uses TLS.
        """

        tpktParser = TPKTParser()
        tls = None
        clientRandom = None
        serverRandom = None
        currentTimeStamp = None
        reconstructingRecord = False
        savedRecord = None
        savedPayload = b""
        tlsKeyGenerated = False

        for packet in self.packets:
            ip = packet.getlayer(IP)
            tcp = packet.getlayer(TCP)

            if len(tcp.payload) == 0 or tcp.flags & TCPFlags.PSH == 0:
                continue

            currentTimeStamp = packet.time
            currentSrcSocket = InetAddress(ip.src, tcp.sport)

            # The first couple messages don't use TLS. Check if it's one of those messages and output it as is.
            if hasattr(tcp, "load") and tpktParser.isTPKTPDU(tcp.load):
                yield PCAPStream.output(tcp.load, currentTimeStamp,
                                        currentSrcSocket,
                                        InetAddress(ip.dst, tcp.dport))
                continue

            # Create the TLS session context.
            if not tls:
                tls = tlsSession(
                    ipsrc=ip.src,
                    ipdst=ip.dst,
                    sport=tcp.sport,
                    dport=tcp.dport,
                    connection_end="server",
                )

            # Makes sure to reassemble TLS stream properly: client <-> server
            if currentSrcSocket != InetAddress(tls.ipsrc, tls.sport):
                tls = tls.mirror()

            # Pass every TLS message through our own custom session so the state is kept properly
            record = packet[TLS]
            record = TLS(bytes(record), tls_session=tls)

            for msg in record.msg:
                if isinstance(msg, TLSClientHello):
                    clientRandom = pkcs_i2osp(msg.gmt_unix_time, 4) + msg.random_bytes
                elif isinstance(msg, TLSServerHello):
                    # TODO: faced some cases where random_bytes was the right length already
                    #       but also it didn't entirely fix that case...
                    #if len(msg.random_bytes) == 32:
                    #    serverRandom = msg.random_bytes
                    #else:
                    serverRandom = pkcs_i2osp(msg.gmt_unix_time, 4) + msg.random_bytes
                elif isinstance(msg, TLSNewSessionTicket):
                    # Session established, set master secret.
                    tls.rcs.derive_keys(
                        client_random=clientRandom,
                        server_random=serverRandom,
                        master_secret=self.masterSecret,
                    )

                    tls.wcs.derive_keys(
                        client_random=clientRandom,
                        server_random=serverRandom,
                        master_secret=self.masterSecret,
                    )

                    tlsKeyGenerated = True
                elif isinstance(msg, TLSApplicationData):
                    yield PCAPStream.output(msg.data, currentTimeStamp,
                                            currentSrcSocket,
                                            InetAddress(ip.dst, tcp.dport))
