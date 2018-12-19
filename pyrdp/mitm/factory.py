#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from twisted.internet.protocol import ClientFactory

from pyrdp.mitm import MITMClient


class MITMClientFactory(ClientFactory):
    def __init__(self, server, fileHandle, socket, replacementUsername, replacementPassword):
        self.server = server
        self.fileHandle = fileHandle
        self.socket = socket
        self.replacementUsername = replacementUsername
        self.replacementPassword = replacementPassword

    def buildProtocol(self, addr):
        # Build protocol for the client side of the connection
        client = MITMClient(self.server, self.fileHandle, self.socket,
                                 self.replacementUsername, self.replacementPassword)

        self.server.setClient(client)
        return client.getProtocol()