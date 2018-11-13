#
# Copyright (c) 2014 Sylvain Peyrefitte
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

"""
unit test for rdpy.protocol.rdp.x224 module
"""

import os, sys
# Change path so we find rdpy
import rdpy.enum.negotiation

sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
import rdpy.protocol.rdp.x224 as x224
import rdpy.core.type as type
import rdpy.core.error as error

class X224Test(unittest.TestCase):
    """
    @summary: test case for x224 layer (RDP)
    """
    
    class X224_PASS(Exception):
        """
        @summary: for OK tests
        """
        pass
    
    class X224_FAIL(Exception):
        """
        @summary: for KO tests
        """
        pass
    
    def test_x224_layer_recvData(self):
        """
        @summary: unit test for X224Layer.recvData function
        """
        class Presentation(object):
            def recv(self, data):
                data.readType(type.String('test_x224_layer_recvData', constant = True))
                raise X224Test.X224_PASS()
                
        layer = x224.X224Layer(Presentation())
        s = type.StringStream()
        s.writeType((x224.X224DataHeader(), type.String('test_x224_layer_recvData')))
        #reinit position
        s.pos = 0
        
        self.assertRaises(X224Test.X224_PASS, layer.recvData, s)
        
    def test_x224_layer_send(self):
        """
        @summary: unit test for X224Layer.send function
        """
        class Transport(object):
            def send(self, data):
                s = type.StringStream()
                s.writeType(data)
                s.pos = 0
                s.readType(x224.X224DataHeader())
                s.readType(type.String('test_x224_layer_send', constant = True))
                raise X224Test.X224_PASS()
        
        layer = x224.X224Layer(None)
        layer._transport = Transport()
        
        self.assertRaises(X224Test.X224_PASS, layer.send, type.String('test_x224_layer_send'))
        
    def test_x224_client_connect(self):
        """
        @summary: unit test for X224Client.connect and sendConnectionRequest function
        """
        class Transport(object):
            def send(self, data):
                s = type.StringStream()
                s.writeType(data)
                s.pos = 0
                t = x224.ClientConnectionRequestPDU()
                s.readType(t)
                
                if t.protocolNeg.code != rdpy.enum.negotiation.NegotiationType.TYPE_RDP_NEG_REQ:
                    raise X224Test.X224_FAIL()
            
        def nextAutomata(data):
            raise X224Test.X224_PASS()
        
        layer = x224.Client(None)
        layer._transport = Transport()        
        layer.recvConnectionConfirm = nextAutomata
        layer.connect()
        
        self.assertRaises(X224Test.X224_PASS, layer.recv, type.String('\x01\x02'))  

    def test_x224_client_recvConnectionConfirm_negotiation_failure(self):
        """
        @summary: unit test for X224Client.recvConnectionConfirm and sendConnectionRequest function
                    check negotiation failure
        """
        message = x224.ServerConnectionConfirm()
        message.protocolNeg.code.value = rdpy.enum.negotiation.NegotiationType.TYPE_RDP_NEG_FAILURE
        s = type.StringStream()
        s.writeType(message)
        s.pos = 0
        layer = x224.Client(None)
        self.assertRaises(error.RDPSecurityNegoFail, layer.recvConnectionConfirm, s)
        
    def test_x224_client_recvConnectionConfirm_ok(self):
        """
        @summary: nominal case of protocol negotiation
        """
        global tls_begin, presentation_connect
        tls_begin = False
        presentation_connect = False
        class Transport(object):

            def startTLS(self, context):
                global tls_begin
                tls_begin = True
                
        class Presentation(object):
            def connect(self):
                global presentation_connect
                presentation_connect = True
                
        def recvData(data):
            raise X224Test.X224_PASS()
        
        message = x224.ServerConnectionConfirm()
        message.protocolNeg.selectedProtocol.value = x224.Protocols.PROTOCOL_SSL
        
        s = type.StringStream()
        s.writeType(message)
        s.pos = 0
        layer = x224.Client(Presentation())
        layer._transport = Transport()
        layer.recvData = recvData
        
        layer.recvConnectionConfirm(s)
        
        self.assertTrue(tls_begin, "TLS is not started")
        self.assertTrue(presentation_connect, "connect event is not forwarded")
        self.assertRaises(X224Test.X224_PASS, layer.recv, type.String('\x01\x02'))
        
    def test_x224_server_recvConnectionRequest_client_accept_ssl(self):
        """
        @summary:  unit test for X224Server.recvConnectionRequest function
                    test client doesn't support TLS case
        """
        
        class Transport(object):
            def send(self, data):
                if not isinstance(data, x224.ServerConnectionConfirm):
                    raise X224Test.X224_FAIL()
                if data.protocolNeg.code.value != rdpy.enum.negotiation.NegotiationType.TYPE_RDP_NEG_FAILURE or data.protocolNeg.failureCode.value != x224.NegotiationFailureCode.SSL_REQUIRED_BY_SERVER:
                    raise X224Test.X224_FAIL()
            def close(self):
                raise X224Test.X224_PASS()
        
        message = x224.ClientConnectionRequestPDU()
        message.protocolNeg.selectedProtocol.value = x224.Protocols.PROTOCOL_HYBRID
        s = type.StringStream()
        s.writeType(message)
        s.pos = 0
        
        layer = x224.Server(None, "key", "cert", True)
        layer._transport = Transport()
        layer.connect()
        
        self.assertRaises(X224Test.X224_PASS, layer.recv, s)
        
    def test_x224_server_recvConnectionRequest_valid(self):
        """
        @summary:  unit test for X224Server.recvConnectionRequest function
        """
        global tls, connect_event
        tls = False
        connect_event = False
        
        class ServerTLSContext(object):
            def __init__(self, key, cert):
                pass
            
        x224.ServerTLSContext = ServerTLSContext
        
        class Transport(object):
            def startTLS(self, context):
                global tls
                tls = True
                        
            def send(self, data):
                if not isinstance(data, x224.ServerConnectionConfirm):
                    raise X224Test.X224_FAIL()
                if data.protocolNeg.code.value != rdpy.enum.negotiation.NegotiationType.TYPE_RDP_NEG_RSP or data.protocolNeg.selectedProtocol.value != x224.Protocols.PROTOCOL_SSL:
                    raise X224Test.X224_FAIL()
                
        class Presentation(object):
            def connect(self):
                global connect_event
                connect_event = True
                
        message = x224.ClientConnectionRequestPDU()
        message.protocolNeg.selectedProtocol.value = x224.Protocols.PROTOCOL_SSL | x224.Protocols.PROTOCOL_RDP
        s = type.StringStream()
        s.writeType(message)
        s.pos = 0
        
        layer = x224.Server(Presentation(), "key", "cert")
        layer._transport = Transport()
        layer.connect()
        layer.recvConnectionRequest(s)
        
        self.assertTrue(tls, "TLS not started")
        self.assertTrue(connect_event, "connect event not forwarded")