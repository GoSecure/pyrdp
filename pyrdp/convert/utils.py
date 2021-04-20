#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import enum

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from pyrdp.convert.JSONEventHandler import JSONEventHandler
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

OUTFILE_FORMAT = "{prefix}{timestamp}_{src}-{dst}"


class TCPFlags(enum.IntEnum):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


def createHandler(format: str, outputFileBase: str, progress=None) -> (str, str):
    """Gets the appropriate handler and returns the filename with extension."""

    if format not in HANDLERS:
        print("[-] Unsupported conversion format.")
        sys.exit(1)

    HandlerClass, ext = HANDLERS[format]
    outputFileBase += f".{ext}"
    return HandlerClass(outputFileBase, progress=progress) if HandlerClass else None, outputFileBase


# noinspection PyUnresolvedReferences
def tcp_both(p) -> str:
    """Session extractor which merges both sides of a TCP channel."""

    if "TCP" in p:
        return str(
            sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str)
        )
    return "Other"


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
    return IP in packet or Ether not in packet

def getSessionInfo(session: PacketList) -> (str, str, float, bool):
    """Attempt to retrieve an (src, dst, ts, isPlaintext) tuple for a data stream."""
    packet = session[0]

    if IP in packet:
        # This is a plaintext stream.
        #
        # FIXME: This relies on the fact that decrypted traces are using EXPORTED_PDU and
        #        thus have no `IP` layer, but it is technically possible to have a true
        #        plaintext capture with very old implementations of RDP.
        return (packet[IP].src, packet[IP].dst, packet.time, False)
    elif Ether not in packet:
        # No Ethernet layer, so assume exported PDUs.
        src = ".".join(str(b) for b in packet.load[12:16])
        dst = ".".join(str(b) for b in packet.load[20:24])
        return (src, dst, packet.time, True)

    raise Exception("Invalid stream type. Must be TCP/TLS or EXPORTED PDU.")
