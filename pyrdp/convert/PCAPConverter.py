#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import math
import traceback
from pathlib import Path
from typing import Dict, List, Tuple

from progressbar import progressbar
from scapy.layers.inet import TCP
from scapy.layers.tls.record import TLS
from pyrdp.convert.pyrdp_scapy import *

from pyrdp.convert.Converter import Converter
from pyrdp.convert.ExportedPDUStream import ExportedPDUStream
from pyrdp.convert.TLSPDUStream import TLSPDUStream
from pyrdp.convert.PCAPStream import PCAPStream
from pyrdp.convert.RDPReplayer import RDPReplayer
from pyrdp.convert.utils import tcp_both, getSessionInfo, findClientRandom, createHandler, canExtractSessionInfo


class PCAPConverter(Converter):
    SESSIONID_FORMAT = "{timestamp}_{src}-{dst}"

    def __init__(self, inputFile: Path, outputPrefix: str, format: str, secrets: Dict = None, srcFilter = None, dstFilter = None, listOnly = False):
        super().__init__(inputFile, outputPrefix, format)
        self.secrets = secrets if secrets is not None else {}
        self.srcFilter = srcFilter if srcFilter is not None else srcFilter
        self.dstFilter = dstFilter if dstFilter is not None else dstFilter
        self.listOnly = listOnly

    def checkSrcExcluded(self, src: str):
        return len(self.srcFilter) > 0 and src not in self.srcFilter

    def checkDstExcluded(self, dst: str):
        return len(self.dstFilter) > 0 and dst not in self.dstFilter

    def process(self):
        streams = self.listSessions()

        if self.listOnly:
            return

        for startTimeStamp, stream in streams:
            try:
                self.processStream(startTimeStamp, stream)
            except Exception as e:
                trace = traceback.format_exc()
                print() # newline
                print(trace)
                print(f"[-] Failed: {e}")

    def listSessions(self) -> List[Tuple[int, PCAPStream]]:
        print(f"[*] Analyzing PCAP '{self.inputFile}' ...")
        bind_layers(TCP, TLS)
        pcap = sniff(offline=str(self.inputFile), session=TCPSession)

        sessions = pcap.sessions(tcp_both)

        if len(sessions.values()) == 0:
            print("No sessions found!")
            return []

        streams: List[Tuple[int, PCAPStream]] = []

        for session in sessions.values():
            if not canExtractSessionInfo(session):
                # Skip unsupported sessions (e.g: UDP sessions and such)
                continue

            client, server, startTimeStamp, plaintext = getSessionInfo(session)

            if self.checkSrcExcluded(client) or self.checkDstExcluded(server):
                continue

            print(f"    - {client} -> {server} :", end="", flush=True)

            if plaintext:
                print(" plaintext")
                stream = ExportedPDUStream(client, server, session)
            else:
                clientRandom = findClientRandom(session)

                if clientRandom in self.secrets:
                    print(" TLS, master secret available (!)")
                    stream = TLSPDUStream(client, server, session, self.secrets[clientRandom]["master"])
                else:
                    print(" TLS, unknown master secret")
                    continue

            streams.append((startTimeStamp, stream))

        return streams

    def processStream(self, startTimeStamp: int, stream: PCAPStream):
        startTimeStamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(math.floor(startTimeStamp)))
        sessionID = PCAPConverter.SESSIONID_FORMAT.format(**{
            "timestamp": startTimeStamp,
            "src": stream.client,
            "dst": stream.server
        })

        handler, _ = createHandler(self.format, self.outputPrefix + sessionID)
        replayer = RDPReplayer(handler, self.outputPrefix, sessionID)

        print(f"[*] Processing {stream.client} -> {stream.server}")

        try:
            for data, timeStamp, src, _dst in progressbar(stream):
                replayer.setTimeStamp(timeStamp)
                replayer.recv(data, src == stream.client)
        except StopIteration:
            # Done processing the stream.
            pass

        try:
            replayer.tcp.recordConnectionClose()
            handler.cleanup()
        except struct.error:
            sys.stderr.write("[!] Couldn't close the session cleanly. Make sure that --src and --dst are correct.")

        print(f"\n[+] Successfully wrote all files to '{self.outputPrefix}'")
