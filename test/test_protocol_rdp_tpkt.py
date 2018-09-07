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
unit test for rdpy.protocol.rdp.tpkt module
"""

import os, sys
# Change path so we find rdpy
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
import rdpy.protocol.rdp.tpkt as tpkt
import rdpy.core.type as type
import rdpy.core.error as error

class TPKTTest(unittest.TestCase):
    """
    @summary: test case for tpkt layer (RDP)
    """
    
    class TPKT_PASS(Exception):
        pass
    
    class TPKT_FAIL(Exception):
        pass
    
    def test_tpkt_layer_connect(self):
        """
        @summary: test forward connect event to presentation layer
        """
        class Presentation(object):
            def connect(self):
                raise TPKTTest.TPKT_PASS()
            
        layer = tpkt.TPKT(Presentation())
        self.assertRaises(TPKTTest.TPKT_PASS, layer.connect)
        
    def test_tpkt_layer_recv(self):
        """
        @summary: test receive in classic case
        """
        class Presentation(object):
            def connect(self):
                pass
            def recv(self, data):
                data.readType(type.String("test_tpkt_layer_recv", constant = True))
                raise TPKTTest.TPKT_PASS()
            
        message = type.String("test_tpkt_layer_recv")
        
        s = type.StringStream()
        s.writeType((type.UInt8(tpkt.Action.FASTPATH_ACTION_X224), type.UInt8(), type.UInt16Be(type.sizeof(message) + 4), message))
        
        layer = tpkt.TPKT(Presentation())
        layer.connect()
        self.assertRaises(TPKTTest.TPKT_PASS, layer.dataReceived, s.getvalue())
        
    def test_tpkt_layer_recv_fastpath(self):
        """
        @summary: test receive in fastpath case
        """
        class FastPathLayer(tpkt.IFastPathListener):
            def setFastPathSender(self, fastPathSender):
                pass
            def recvFastPath(self, secFlag, fastPathS):
                fastPathS.readType(type.String("test_tpkt_layer_recv_fastpath", constant = True))
                raise TPKTTest.TPKT_PASS()
            
        message = type.String("test_tpkt_layer_recv_fastpath")
        
        s = type.StringStream()
        s.writeType((type.UInt8(tpkt.Action.FASTPATH_ACTION_FASTPATH), type.UInt8(type.sizeof(message) + 2), message))
        
        layer = tpkt.TPKT(None)
        layer.initFastPath(FastPathLayer())
        layer.connect()
        self.assertRaises(TPKTTest.TPKT_PASS, layer.dataReceived, s.getvalue())
        
    def test_tpkt_layer_recv_fastpath_ext_length(self):
        """
        @summary: test receive in fastpath case with extended length
        """
        class FastPathLayer(tpkt.IFastPathListener):
            def setFastPathSender(self, fastPathSender):
                pass
            def recvFastPath(self, secflag, fastPathS):
                fastPathS.readType(type.String("test_tpkt_layer_recv_fastpath_ext_length", constant = True))
                raise TPKTTest.TPKT_PASS()
            
        message = type.String("test_tpkt_layer_recv_fastpath_ext_length")
        
        s = type.StringStream()
        s.writeType((type.UInt8(tpkt.Action.FASTPATH_ACTION_FASTPATH), type.UInt16Be((type.sizeof(message) + 3) | 0x8000), message))
        
        layer = tpkt.TPKT(None)
        layer.initFastPath(FastPathLayer())
        layer.connect()
        self.assertRaises(TPKTTest.TPKT_PASS, layer.dataReceived, s.getvalue())
