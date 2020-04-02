#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.logging import LOGGER_NAMES, SessionLogger
from pyrdp.mitm import MITMConfig, RDPMITM
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.state import RDPMITMState
from pyrdp.recording import FileLayer

import argparse
from binascii import unhexlify, hexlify
import logging
from pathlib import Path
import struct
import time

from progressbar import progressbar

# No choice but to import * here for load_layer to work properly.
from scapy.all import *  # noqa
load_layer('tls')  # noqa

TLS_HDR_LEN = 24  # Hopefully this doesn't change between TLS versions.


class CustomMITMRecorder(MITMRecorder):
    currentTimeStamp: int = None

    def getCurrentTimeStamp(self) -> int:
        return self.currentTimeStamp

    def setTimeStamp(self, timeStamp: int):
        self.currentTimeStamp = timeStamp


class RDPReplayerConfig(MITMConfig):
    @property
    def replayDir(self) -> Path:
        return self.outDir

    @property
    def fileDir(self) -> Path:
        return self.outDir


class RDPReplayer(RDPMITM):
    def __init__(self, output_path: str):
        def sendBytesStub(_: bytes):
            pass

        output_path = Path(output_path)
        output_directory = output_path.absolute().parent

        logger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
        log = SessionLogger(logger, "replay")

        config = RDPReplayerConfig()
        config.outDir = output_directory
        # We'll set up the recorder ourselves
        config.recordReplays = False

        replay_transport = FileLayer(output_path)
        state = RDPMITMState(config)
        super().__init__(log, log, config, state, CustomMITMRecorder([replay_transport], state))

        self.client.tcp.sendBytes = sendBytesStub
        self.server.tcp.sendBytes = sendBytesStub
        self.state.useTLS = True

    def start(self):
        pass

    def recv(self, data: bytes, from_client: bool):
        if from_client:
            self.client.tcp.dataReceived(data)
        else:
            self.server.tcp.dataReceived(data)

    def setTimeStamp(self, timeStamp: float):
        self.recorder.setTimeStamp(int(timeStamp * 1000))

    def connectToServer(self):
        pass

    def startTLS(self):
        pass

    def sendPayload(self):
        pass

# The name format of output files.
OUTFILE_FORMAT = '{prefix}{timestamp}_{src}-{dst}.{ext}'


def findClientRandom(stream: PacketList, limit: int = 10) -> str:
    """Find the client random offset and value of a stream."""
    for n, p in enumerate(stream):
        if n >= limit:
            return ''  # Didn't find client hello.
        try:
            tls = TLS(p.load)
            hello = tls.msg[0]
            if not isinstance(hello, TLSClientHello):
                continue
            return hexlify(pkcs_i2osp(hello.gmt_unix_time, 4) + hello.random_bytes).decode()
        except Exception:
            pass  # Not a TLS packet.
    return ''


def tcp_both(p) -> str:
    """Session extractor which merges both sides of a TCP channel."""

    if 'TCP' in p:
        return str(sorted(['TCP', p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport], key=str))
    return 'Other'


def loadSecrets(filename: str) -> dict:
    secrets = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line == '' or not line.startswith('CLIENT'):
                continue

            parts = line.split(' ')
            if len(parts) != 3:
                continue

            [t, c, m] = parts

            # Parse the secret accordingly.
            if t == 'CLIENT_RANDOM':
                secrets[c] = { 'client': unhexlify(c), 'master': unhexlify(m) }
    return secrets


class Decrypted:
    """Class for keeping decryption state of a TLS stream."""
    def __init__(self, stream: PacketList, secret: bytes):
        # Iterator State.
        self.stream = stream
        self.ipkt = iter(stream)

        # TLS State.
        self.secret = secret
        self.client = None
        self.server = None
        self.tls = None

        # Data Flow State.
        self.src = None
        self.dst = None

    def __iter__(self):
        return self

    def __next__(self):
        p = next(self.ipkt)
        ip = p.getlayer(IP)
        tcp = p.getlayer(TCP)

        if len(tcp.payload) == 0:
            return p  # Not application data.

        if not self.src:
            # First packet in the stream, establish sending and receiving ends.
            self.src = self.last = ip.src
            self.dst = ip.dst
            # Create the TLS session context.
            self.tls = tlsSession(ipsrc=ip.src, ipdst=ip.dst, sport=tcp.sport, dport=tcp.dport, connection_end='server')

        # Mirror the session if the packet is flowing in the opposite direction.
        if self.tls.ipsrc != ip.src:
            self.tls = self.tls.mirror()

        try:
            frame = TLS(p.load, tls_session=self.tls)
        except AttributeError as e:
            if not self.client:
                return p  # ClientHelo is not sent yet: This is not TLS data.
            else:
                raise e  # Should be TLS data.

        # Perform PDU reassembly.
        if TLSApplicationData in frame:
            payload = p.load
            # There could be multiple nested TLS records within the
            # same TCP packet. In that case we need to consume packets
            # until The last layer is complete, otherwise it becomes
            # extremely difficult to decrypt the rest of the stream.
            tls = frame.lastlayer()
            while tls.len - tls.deciphered_len - TLS_HDR_LEN > 0:
                fragment = next(self.ipkt)

                if Raw not in fragment:
                    continue  # Skip TCP control.

                payload += fragment.load
                frame = TLS(payload, tls_session=self.tls)
                tls = frame.lastlayer()

        # FIXME: Maybe rebuild each TLSApplicationData to be a message entry in a single record?
        tcp.remove_payload()
        tcp.add_payload(frame)
        self.tlsSession = frame.tls_session  # Update TLS Context.

        # FIXME: Rather, check if the message is included in it to be sure?
        msg = frame.msg[0]
        if isinstance(msg, TLSClientHello):
            self.client = pkcs_i2osp(msg.gmt_unix_time, 4) + msg.random_bytes
        elif isinstance(msg, TLSServerHello):
            self.server = pkcs_i2osp(msg.gmt_unix_time, 4) + msg.random_bytes

        elif isinstance(msg, TLSNewSessionTicket):
            # Session established, set master secret.
            self.tls.rcs.derive_keys(client_random=self.client,
                                    server_random=self.server,
                                    master_secret=self.secret)

            self.tls.wcs.derive_keys(client_random=self.client,
                                    server_random=self.server,
                                    master_secret=self.secret)
        return p


def decrypted(stream: PacketList, master_secret: bytes) -> Decrypted:
    """An iterator function that decrypts a stream."""
    return Decrypted(stream, master_secret)


def getStreamInfo(s: PacketList) -> (str, str, float, bool):
    """Attempt to retrieve an (src, dst, ts, isPlaintext) tuple for a data stream."""
    packet = s[0]
    if IP in packet:
        # FIXME: Technically the IP traffic could be plaintext too.
        return (packet[IP].src, packet[IP].dst, packet.time, False)
    elif Ether not in packet:
        # No Ethernet layer, so assume exported PDUs.
        src = ".".join(str(b) for b in packet.load[12:16])
        dst = ".".join(str(b) for b in packet.load[20:24])
        return (src, dst, float(packet.time) / 1000, True)
    raise Exception('Invalid stream type. Must be TCP/TLS or EXPORTED PDU.')


def processPlaintext(stream: PacketList, outfile: str, info):
    """Process a plaintext EXPORTED PDU RDP export to a replay."""
    replayer = RDPReplayer(outfile)
    (client, server, _, _) = info
    for packet in progressbar(stream):
        src = ".".join(str(b) for b in packet.load[12:16])
        dst = ".".join(str(b) for b in packet.load[20:24])
        data = packet.load[60:]

        if src not in [client, server] or dst not in [client, server]:
            continue

        # FIXME: The absolute time is completely wrong here because replayer multiplies by 1000.
        replayer.setTimeStamp(float(packet.time))
        replayer.recv(data, src == client)

    try:
        replayer.tcp.recordConnectionClose()
    except struct.error:
        print("Couldn't close the connection cleanly. "
              "Are you sure you got source and destination correct?")


def processTLS(stream: Decrypted, outfile: str):
    """Process an encrypted TCP stream into a replay file."""
    # print(f'Processing {stream.src} <> {stream.dst}')
    replayer = RDPReplayer(outfile)
    client = None  # The RDP client's IP.

    for packet in progressbar(stream):
        ip = packet.getlayer(IP)

        if not client:
            client = ip.src
            continue

        if TLSApplicationData not in packet:
            # This is not TLS application data, skip it, as PyRDP's
            # network stack cannot parse TLS handshakes.
            continue

        ts = float(packet.time)
        for payload in packet[TLS].iterpayloads():
            if TLSApplicationData not in payload:
                continue  # Not application data.
            for m in payload.msg:
                replayer.setTimeStamp(ts)
                replayer.recv(m.data, ip.src == client)
    try:
        replayer.tcp.recordConnectionClose()
    except struct.error:
        print("Couldn't close the connection cleanly. "
              "Are you sure you got source and destination correct?")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', help='Path to a .pcap, .pcapng, or .pyrdp file')
    parser.add_argument('-l', '--list', help='Print the list of sessions in the capture without processing anything', action='store_true')
    parser.add_argument('-s', '--secrets', help='Path to the file containing the SSL secrets to decrypt Transport Layer Security.')
    parser.add_argument('-f', '--format', help='Format of the output', choices=['replay', 'mp4'], default='replay')
    parser.add_argument('--src', help='If specified, limits the converted streams to connections initiated from this address', action='append', default=[])
    parser.add_argument('--dst', help='If specified, limits the converted streams to connections destined to this address', action='append', default=[])
    parser.add_argument('-o', '--output', help='Path to write the converted files to. If a file name is specified, it will be used as a prefix.')
    args = parser.parse_args()

    logging.basicConfig(level=logging.CRITICAL)
    logging.getLogger("scapy").setLevel(logging.ERROR)
    # logging.getLogger("pyrdp").setLevel(logging.DEBUG)

    # -- PCAPS ------------------------------------------------
    secrets = loadSecrets(args.secrets) if args.secrets else {}

    print('[*] Analyzing network trace...')
    pcap = sniff(offline=args.input)
    sessions = pcap.sessions(tcp_both)
    streams = []
    for stream in sessions.values():
        (src, dst, ts, plaintext) = info = getStreamInfo(stream)
        name = f'{src} -> {dst}'
        print(f"    - {src} -> {dst}:", end ='', flush=True)

        if plaintext:
            print(' plaintext')
            streams.append((info, stream))
            continue

        rnd = findClientRandom(stream)
        if rnd not in secrets and rnd != '':
            print(' unknown master secret')
        else:
            print(' master secret available (!)')
            streams.append((info, decrypted(stream, secrets[rnd]['master'])))

    if args.list:
        return

    for (src, dst, ts, plaintext), s in streams:
        if len(args.src) > 0 and src not in args.src:
            continue
        if len(args.dst) > 0 and dst not in args.dst:
            continue
        try:
            print(f'[*] Processing {src} -> {dst}')
            ts = time.strftime('%Y%M%d%H%m%S', time.gmtime(ts))
            outfile = OUTFILE_FORMAT.format(**{'prefix': 'converted-', 'timestamp': ts, 'src': src, 'dst': dst, 'ext': 'pyrdp'})

            if plaintext:
                processPlaintext(s, outfile, info)
            else:
                processTLS(s, outfile)

            print(f"\n[+] Successfully wrote '{outfile}'")
        except Exception as e:
            print('\n[-] Failed to extract stream. Verify that all packets are in the trace and that the master secret is the right one.')
            raise e
    # -- /PCAPS -----------------------------------------------


if __name__ == "__main__":
    main()
