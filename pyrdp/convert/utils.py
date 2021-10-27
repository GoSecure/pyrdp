#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import enum
from typing import Tuple

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pyrdp.convert.JSONEventHandler import JSONEventHandler
from pyrdp.core import Uint32BE
from pyrdp.player import HAS_GUI

from pyrdp.convert.pyrdp_scapy import *

"""
Supported conversion handlers.

The class constructor signature must be `__init__(self, output_path: str, progress=None)`
"""
HANDLERS = {"replay": (None, "pyrdp"), "json": (JSONEventHandler, "json")}

if HAS_GUI:
    from pyrdp.convert.MP4EventHandler import MP4EventHandler
    HANDLERS["mp4"] = (MP4EventHandler, "mp4")
else:
    # Class stub for when MP4 support is not available.
    # It would be a good idea to refactor this so that Mp4EventHandler is
    # acquired through some factory object that checks for GUI support
    # once we add more conversion handlers.
    class MP4EventHandler():
        def __init__(self, _unused: str):
            pass


class TCPFlags(enum.IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class InetAddress():
    def __init__(self, ip: str, port: int):
        self._ip = ip
        self._port = port

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def port(self) -> int:
        return self._port

    def __eq__(self, other):
        if self.ip == other.ip and self.port == other.port:
            return True
        else:
            return False

    def __str__(self):
        return f"{self._ip}:{self._port}"


def extractInetAddressesFromPDUPacket(packet) -> Tuple[InetAddress, InetAddress]:
    """Returns the src and dst InetAddress (IP, port) from a PDU packet"""
    return (InetAddress(".".join(str(b) for b in packet.load[12:16]),
                        Uint32BE.unpack(packet.load[36:40])),
            InetAddress(".".join(str(b) for b in packet.load[20:24]),
                        Uint32BE.unpack(packet.load[44:48])))


def createHandler(format: str, outputFileBase: str, progress=None) -> Tuple[str, str]:
    """
    Gets the appropriate handler and returns the filename with extension.
    Returns None if the format is replay.
    TODO: Returning None if the format is replay is kind of janky. This could use a refactor to handle replays and other formats differently.
    """

    if format not in HANDLERS:
        print("[-] Unsupported conversion format.")
        sys.exit(1)

    HandlerClass, ext = HANDLERS[format]
    outputFileBase += f".{ext}"
    return HandlerClass(outputFileBase, progress=progress) if HandlerClass else None, outputFileBase


class Exported(Packet):
    """60 byte EXPORTED_PDU header."""
    # We could properly parse the EXPORTED_PDU struct, but we are mostly dealing with IP exported PDUs
    # so let's just wing it.
    name = "Exported"
    fields_desc = [ 
                    IntField("tag1Num", None),  # 4
                    StrFixedLenField("proto", None, length=4),  # 8
                    IntField("tag2Num", None),  # 12
                    IPField("src", None),  # 16
                    IntField("tag3Num", None),  # 20
                    IPField("dst", None),  # 24
                    IntField("tag4Num", None),  # 28
                    IntField("portType", None),  # 32
                    IntField("tag5Num", None),  # 36
                    IntField("sport", None),  # 40
                    IntField("tag6Num", None),  # 44
                    IntField("dport", None),  # 48
                    IntField("tag7Num", None),  # 52
                    IntField("frame", None),   # 56
                    IntField("endOfTags", None),  # 60
    ]


# noinspection PyUnresolvedReferences
def tcp_both(p) -> str:
    """Session extractor which merges both sides of a TCP channel."""

    if "TCP" in p:
        return str(
            sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str)
        )

    # Need to make sure this is OK when non-TCP, non-exported data is present.
    if Ether not in p:
        x = Exported(p.load)
        return str(
                sorted([x.proto.upper(), x.src, x.sport, x.dst, x.dport], key=str)
        )

    return "Unsupported"


# noinspection PyUnresolvedReferences
def findClientRandom(stream: PacketList, limit: int = 20) -> str:
    """Find the client random offset and value of a stream."""
    for n, p in enumerate(stream):
        if n >= limit:
            return ""  # Didn't find client hello.
        try:
            tls = p[TCP].payload
            hello = tls.msg[0]
            if isinstance(hello, TLSClientHello):
                return (pkcs_i2osp(hello.gmt_unix_time, 4) + hello.random_bytes).hex()
        except AttributeError as e:
            continue  # Not a TLS packet.

    return ""


def loadSecrets(filename: str) -> dict:
    secrets = {}
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if line == "" or not line.startswith("CLIENT"):
                continue

            parts = line.split(" ")
            if len(parts) != 3:
                continue

            [t, c, m] = parts

            # Parse the secret accordingly.
            if t == "CLIENT_RANDOM":
                secrets[c] = {"client": bytes.fromhex(c), "master": bytes.fromhex(m)}
    return secrets

def canExtractSessionInfo(session: PacketList) -> bool:
    packet = session[0]
    # TODO: Eventually we should be able to wrap the session as an ExportedSession
    # and check for the presence of exported.
    return IP in packet or Ether not in packet

def getSessionInfo(session: PacketList) -> Tuple[InetAddress, InetAddress, float, bool]:
    """Attempt to retrieve an (src, dst, ts, isPlaintext) tuple for a data stream."""
    packet = session[0]

    # FIXME: This relies on the fact that decrypted traces are using EXPORTED_PDU and
    #        thus have no `Ether` layer, but it is technically possible to have a true
    #        plaintext capture with very old implementations of RDP.
    if TCP in packet:
        # Assume an encrypted stream...
        return (InetAddress(packet[IP].src, packet[IP][TCP].sport),
                InetAddress(packet[IP].dst, packet[IP][TCP].dport),
                packet.time, False)
    elif Ether not in packet:
        # No Ethernet layer, so assume exported PDUs.
        src, dst = extractInetAddressesFromPDUPacket(packet)
        return (src, dst, packet.time, True)

    raise Exception("Invalid stream type. Must be TCP/TLS or EXPORTED PDU.")