#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio

from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())

import argparse
import logging
import sys

import OpenSSL
from twisted.application.reactors import Reactor
from twisted.internet import reactor
from twisted.internet.endpoints import HostnameEndpoint
from twisted.internet.protocol import ClientFactory

from pyrdp.core.ssl import ClientTLSContext
from pyrdp.enum import NegotiationProtocols
from pyrdp.layer import TPKTLayer, TwistedTCPLayer, X224Layer, LayerChainItem
from pyrdp.logging import LOGGER_NAMES
from pyrdp.parser.rdp.negotiation import NegotiationRequestParser
from pyrdp.pdu.rdp.negotiation import NegotiationRequestPDU


class TCPCertFetchingLayer(TwistedTCPLayer):
    """
    TCP layer that saves the TLS certificate after startTLS is complete, then shuts down Twisted.
    """

    def __init__(self):
        super().__init__()
        self.cert: OpenSSL.crypto.X509 = None

    def logSSLParameters(self):
        # We don't need this in this tool.
        pass

    def startTLS(self, tlsContext):
        TwistedTCPLayer.startTLS(self, tlsContext)

        # Callback in a couple seconds to inspect the TLS certificate
        reactor.callLater(2, self.saveCertificate)

    def saveCertificate(self):
        self.cert = self.transport.getPeerCertificate()
        reactor.stop()


class CertFetcher(ClientFactory):
    """
    Client factory that orchestrates the certificate fetching.
    """

    def __init__(self, _reactor: Reactor, host: str, port: int):
        self.reactor = _reactor
        self.host = host
        self.port = port
        self.log = logging.getLogger(f"{LOGGER_NAMES.PYRDP}.clonecert")
        self.tcp = TCPCertFetchingLayer()
        self.tpkt = TPKTLayer()
        self.x224 = X224Layer()

        LayerChainItem.chain(self.tcp, self.tpkt, self.x224)
        self.tcp.createObserver(onConnection=self.sendConnectionRequest)
        self.x224.createObserver(onConnectionConfirm=lambda _: self.startTLS())

    def buildProtocol(self, addr):
        return self.tcp

    def fetch(self):
        endpoint = HostnameEndpoint(reactor, self.host, self.port)
        endpoint.connect(self)
        self.reactor.run()

        return self.tcp.cert

    def sendConnectionRequest(self):
        self.log.info("Connected to RDP server")

        negotiationRequest = NegotiationRequestPDU(None, 0, NegotiationProtocols.SSL | NegotiationProtocols.CRED_SSP)
        negoParser = NegotiationRequestParser()
        payload = negoParser.write(negotiationRequest)
        self.x224.sendConnectionRequest(payload)

    def startTLS(self):
        self.log.info("Starting TLS")
        self.tcp.startTLS(ClientTLSContext())


def prepareLoggers(logLevel: int):
    formatter = logging.Formatter("[{asctime}] - {levelname} - {name} - {message}", style = "{")

    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    pyrdpLogger = logging.getLogger(LOGGER_NAMES.PYRDP)
    pyrdpLogger.addHandler(streamHandler)
    pyrdpLogger.setLevel(logLevel)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="RDP host to clone")
    parser.add_argument("out_file", help="Output certificate file name")
    parser.add_argument("-p", "--port", help="RDP port of the host (default 3389)", default=3389, type=int)
    parser.add_argument("-L", "--log-level", help="Log level (default: INFO)", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], nargs="?")

    keyGroup = parser.add_mutually_exclusive_group(required=True)
    keyGroup.add_argument("-o", "--out-key", help="Path used when saving the generated private key")
    keyGroup.add_argument("-i", "--in-key", help="Private key to use when signing the fake certificate (default: generate a new key)")

    arguments = parser.parse_args()

    if arguments.port < 1 or arguments.port > 65535:
        print("Port must be a number between 1 and 65535", file=sys.stderr)
        sys.exit(1)

    key: OpenSSL.crypto.PKey = None

    if arguments.in_key is not None:
        try:
            with open(arguments.in_key, "rb") as f:
                keyBytes = f.read()
        except IOError as e:
            print(f"Input key: {e}", file=sys.stderr)
            sys.exit(1)

        key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, keyBytes)

    logLevel = getattr(logging, arguments.log_level)
    prepareLoggers(logLevel)
    clonerLog = logging.getLogger(f"{LOGGER_NAMES.PYRDP}.clonecert")

    cloner = CertFetcher(reactor, arguments.host, arguments.port)
    cert = cloner.fetch()

    if not key:
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, cert.get_pubkey().bits())
    else:
        if key.bits() != cert.get_pubkey().bits():
            clonerLog.warning("Input and server key bits are different: input: %(inBits)d bits, server: %(serverBits)d. You may want to use a key that matches the server.", {
                "inBits": key.bits(),
                "serverBits": cert.get_pubkey().bits()
            })

    # Actual type is str, but this prevents warnings
    digestAlgorithm: bytes = cert.get_signature_algorithm().decode()

    if digestAlgorithm in ["md4", "md5"]:
        defaultDigestAlgorithm = "sha256"

        answer = input(
            f"The digest algorithm used by the server ('{digestAlgorithm}') is too weak and will not work with the PyRDP MITM. " +
            f"Do you want to change the digest algorithm to {defaultDigestAlgorithm}? [Y/n]"
        )

        if answer == "" or answer[0].upper() == "Y":
            clonerLog.info(f"Digest algorithm changed from {digestAlgorithm} to {defaultDigestAlgorithm}")
            digestAlgorithm = defaultDigestAlgorithm

    cert.set_pubkey(key)
    cert.sign(key, digestAlgorithm)

    clonerLog.info("Saving certificate to %(certPath)r", {"certPath": arguments.out_file})

    try:
        with open(arguments.out_file, "wb") as f:
            f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
    except IOError as e:
        print(f"Output file: {e}", file=sys.stderr)
        sys.exit(1)

    if arguments.out_key is not None:
        clonerLog.info("Saving private key to %(keyPath)r", {"keyPath": arguments.out_key})

        try:
            with open(arguments.out_key, "wb") as f:
                f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        except IOError as e:
            print(f"Output key: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()