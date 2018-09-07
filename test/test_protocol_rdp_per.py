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
unit test for rdpy.protocol.rdp.per module
"""

import os, sys
# Change path so we find rdpy
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
import rdpy.protocol.rdp.t125.per as per
import rdpy.core.type as type
import rdpy.core.error as error

class PERTest(unittest.TestCase):
    """
    @summary: test case for per layer (RDP)
    """
    
    def test_per_readLength(self):
        """
        @summary: test readLength function in per module
        """
        s1 = type.StringStream()
        s1.writeType(type.UInt8(0x1a))
        s1.pos = 0
        
        l1 = per.readLength(s1)
        
        self.assertTrue(l1 == 0x1a, "readLength fail in small format")
        
        s2 = type.StringStream()
        s2.writeType(type.UInt16Be(0x1abc | 0x8000))
        s2.pos = 0
        
        l2 = per.readLength(s2)
        
        self.assertTrue(l2 == 0x1abc, "readLength fail in big format")
        
    def test_per_writeLength(self):
        """
        @summary: test writeLength function in per module
        """
        l1 = per.writeLength(0x1a)
        self.assertTrue(isinstance(l1, type.UInt8), "bad write length type in small case")
        
        l2 = per.writeLength(0x7f)
        self.assertTrue(isinstance(l2, type.UInt8), "bad write length type in small case limit")
        
        l3 = per.writeLength(0x80)
        self.assertTrue(isinstance(l3, type.UInt16Be), "bad write length type in large case limit")
        
        l4 = per.writeLength(0xab)
        self.assertTrue(isinstance(l4, type.UInt16Be), "bad write length type in large case")
        
    def test_per_readInteger(self):
        """
        @summary: test readInteger function in per module
        """
        for t in [type.UInt8, type.UInt16Be, type.UInt32Be]:
            v = t(3)
            s = type.StringStream()
            s.writeType((per.writeLength(type.sizeof(v)), v))
            s.pos = 0
            
            self.assertTrue(per.readInteger(s) == 3, "invalid readLength for type %s"%t)
        
        #error case
        for l in [0, 3, 5]:
            s = type.StringStream()
            s.writeType(per.writeLength(l))
            s.pos = 0
            
            self.assertRaises(error.InvalidValue, per.readInteger, s)
            
    def test_per_writeInteger(self):
        """
        @summary: test writeInteger function in per module
        """
        (s, i) = per.writeInteger(0xaf)
        self.assertTrue(s.value == 1 and isinstance(i, type.UInt8), "invalid writeLength output in case of size 1")
        
        (s, i) = per.writeInteger(0xaff)
        self.assertTrue(s.value == 2 and isinstance(i, type.UInt16Be), "invalid writeLength output in case of size 2")
        
        (s, i) = per.writeInteger(0xaffff)
        self.assertTrue(s.value == 4 and isinstance(i, type.UInt32Be), "invalid writeLength output in case of size 4")
        
    