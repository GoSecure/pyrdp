#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

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
