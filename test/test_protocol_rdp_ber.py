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
unit test for rdpy.protocol.rdp.ber module
"""

import os, sys
# Change path so we find rdpy
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
import rdpy.protocol.rdp.t125.ber as ber
import rdpy.core.type as type
import rdpy.core.error as error

class BERTest(unittest.TestCase):
    """
    @summary: test case for ber layer (RDP)
    """
    
    def test_ber_readLength(self):
        """
        @summary: test readLength function in ber module
        """
        s1 = type.StringStream()
        s1.writeType(type.UInt8(0x1a))
        s1.pos = 0
        
        l1 = ber.readLength(s1)
        
        self.assertTrue(l1 == 0x1a, "readLength fail in small format")
        
        s2 = type.StringStream()
        s2.writeType((type.UInt8(0x81),type.UInt8(0xab)))
        s2.pos = 0
        
        l2 = ber.readLength(s2)
        
        self.assertTrue(l2 == 0xab, "readLength fail in big format of size 1")
        
        s3 = type.StringStream()
        s3.writeType((type.UInt8(0x82),type.UInt16Be(0xabab)))
        s3.pos = 0
        
        l3 = ber.readLength(s3)
        
        self.assertTrue(l3 == 0xabab, "readLength fail in big format of size 2")

    def test_ber_writeLength(self):
        """
        @summary: test writeLength function in ber module
        """
        l1 = ber.writeLength(0x1a)
        self.assertTrue(isinstance(l1, type.UInt8), "bad write length type in small case")
        
        l2 = ber.writeLength(0x7f)
        self.assertTrue(isinstance(l2, type.UInt8), "bad write length type in small case limit")
        
        (h3, l3) = ber.writeLength(0x80)
        self.assertTrue(h3.value == 0x82 and isinstance(l3, type.UInt16Be), "bad write length type in large case limit")
        
        (h4, l4) = ber.writeLength(0xab)
        self.assertTrue(h4.value == 0x82 and isinstance(l4, type.UInt16Be), "bad write length type in large case")