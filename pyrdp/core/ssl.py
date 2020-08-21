#
# Copyright (c) 2014-2020 Sylvain Peyrefitte
# Copyright (c) 2020 GoSecure Inc.
#
# This file is part of the PyRDP project.
#
# Licensed under the GPLv3 or later.
#

from os import path

import OpenSSL
from OpenSSL import SSL

from twisted.internet import ssl


class ClientTLSContext(ssl.ClientContextFactory):
    """
    @summary: client context factory for open ssl
    """

    def getContext(self):
        # Allow the MITM to connect to an RDP Server with ANY TLS version supported by the installed
        # OpenSSL version. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=784153
        # It was removed from OpenSSL, but PyOpenSSL has not changed their constant names yet.
        context = SSL.Context(SSL.SSLv23_METHOD)
        context.set_options(SSL.OP_DONT_INSERT_EMPTY_FRAGMENTS)
        context.set_options(SSL.OP_TLS_BLOCK_PADDING_BUG)

        # We disable TLS 1.3 because the way to decrypt TLS 1.3 traffic differs from
        # previous TLS versions and is not yet supported by PyRDP.
        context.set_options(SSL.OP_NO_TLSv1_3)
        return context


class ServerTLSContext(ssl.DefaultOpenSSLContextFactory):
    """
    @summary: Server context factory for open ssl
    @param privateKeyFileName: Name of a file containing a private key
    @param certificateFileName: Name of a file containing a certificate
    """

    def __init__(self, privateKeyFileName, certificateFileName):
        class TPDUSSLContext(SSL.Context):
            def __init__(self, method):
                SSL.Context.__init__(self, method)
                self.set_options(SSL.OP_DONT_INSERT_EMPTY_FRAGMENTS)
                self.set_options(SSL.OP_TLS_BLOCK_PADDING_BUG)

                # See comment in ClientTLSContext
                self.set_options(SSL.OP_NO_TLSv1_3)

        # See comment in ClientTLSContext
        ssl.DefaultOpenSSLContextFactory.__init__(self, privateKeyFileName, certificateFileName, SSL.SSLv23_METHOD,
                                                  TPDUSSLContext)


class CertificateCache():
    """
    Handle multiple certificates.
    """

    def __init__(self, cachedir):
        self._root = cachedir

    def clone(self, cert: OpenSSL.crypto.X509) -> (OpenSSL.crypto.PKey, OpenSSL.crypto.X509):
        """Clone the provided certificate."""

        # Generate a private key for the server.
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, cert.get_pubkey().bits())

        # Actual type is str, but this prevents warnings
        digestAlgorithm: bytes = cert.get_signature_algorithm().decode()

        # Force digest algorithm to be sha256
        if digestAlgorithm in ["md4", "md5"]:
            digestAlgorithm = "sha256"

        cert.set_pubkey(key)
        cert.sign(key, digestAlgorithm)

        return key, cert

    def lookup(self, cert: OpenSSL.crypto.X509) -> (str, str):
        subject = cert.get_subject()
        parts = dict(subject.get_components())
        commonName = parts[b'CN'].decode()
        base = str(self._root / commonName)

        if path.exists(base + '.pem'):
            # Recover cache entry from disk.
            privKey = base + '.pem'
            certFile = base + '.crt'
            return privKey, certFile
        else:
            priv, cert = self.clone(cert)
            privKey = base + '.pem'
            certFile = base + '.crt'

            # Save Certificate to disk
            with open(certFile, "wb") as f:
                f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

            with open(privKey, "wb") as f:
                f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, priv))

            return privKey, certFile
