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
unit test for rdpy.protocol.rdp.lic automata
"""

import os, sys
# Change path so we find rdpy
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import unittest
from rdpy.protocol.rdp import lic, sec
import rdpy.core.type as type

#dump of server request
SERVERREQUEST = """
AQNfCBkr6c1CVLRPx7PPYVgzW5uMQ1pSvtzs9XlTt74jwjslAAAGACwAAABNAGkAYwByAG8AcwBv
AGYAdAAgAEMAbwByAHAAbwByAGEAdABpAG8AbgAAAAgAAABBADAAMgAAAA0ABAABAAAAAwDZBwIA
AAACAAAAWAMAADCCA1QwggJAoAMCAQICCAGemF/kFo3QMAkGBSsOAwIdBQAwODE2MBUGA1UEBx4O
AFMASQBSAEEARABFAEwwHQYDVQQDHhYAVgBTAEkALQBTAFIAVgAtADAAMAA0MB4XDTcwMTAyMTA4
MDMxN1oXDTQ5MTAyMTA4MDMxN1owODE2MBUGA1UEBx4OAFMASQBSAEEARABFAEwwHQYDVQQDHhYA
VgBTAEkALQBTAFIAVgAtADAAMAA0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0mh+
rgsNk7WCR8Ck46jTV6OgnMgsFmdt0RqBJqtFwk+uqH8cBKFohtD9CeHTeQYkk+8m1C5GDpjQ/5BK
jaBfZHW+g5lZQITKbTi2n8TZfDg76wHvfl71JzwB84AG736KOZSOkBg8mJk3xf8LX5hbYHPQCRc5
y+06CWOyPiBYCEElXPOqsZYwum72N/NIsrKe98QHLn+X6MSbZ9Qzw6jnoBFgjk65bzpcChaOhnlW
875D6+8KZXgFmHT6MSJX7eabKw1zbKXszYpPvPfMDybp+6z125AJ+GxJ847AQ10xOV2X13ZVfSvS
Np62ogDD23duWHvcwLmHJ+45Jdgt7y4C0wIDAQABo2owaDAPBgNVHRMECDAGAQH/AgEAMFUGCSsG
AQQBgjcSCARIQwBDAFIATQBWAEoANgBWAEMAVABUAFcAUgBXAEcATQA4AEgASwBIAFkAMwBKAEsA
OABXADMAVgBNAEIARABXAFQAUQBGAAAAMAkGBSsOAwIdBQADggEBAD2NQPpBREuD+CZI9T4bUF9s
2yyQ8HidxJ+7NMcDyW4Ozid/SrAT9JP42RQrBosgq8S8teWNubrsNMsJjGaeueeQisLP1OigXQH1
8DcnLUc5TZKIsKjBqxJ40tssR5KaOfjGHXX5VoADsthnp3wO4bRuaXyhpLQzN1bUNKQk0Fok6Fzt
zo/rNEiAQv+M/Y1vmCoTuulXwxymZ+UdbxHPr/IvmxD0Gcmz8Qm45Lpypt2t0lGwNiuV2/3dm13C
spjIGxJFf/26QiRuZi5cps2YsOaQfW3xByklE5EbZWYIlsTCQpht+owKqnoPy7aD2On8z0IyGgY3
YdsOzHDvRZ+S0hxhBAAAMIIEXTCCA0mgAwIBAgIFAQAAABgwCQYFKw4DAh0FADA4MTYwFQYDVQQH
Hg4AUwBJAFIAQQBEAEUATDAdBgNVBAMeFgBWAFMASQAtAFMAUgBWAC0AMAAwADQwHhcNMTMxMTI3
MTQyNDIyWhcNMzgwMTE5MDMxNDA3WjCBqDGBpTAnBgNVBAMeIABuAGMAYQBjAG4AXwBuAHAAOgAx
ADkAMgAuADEANgA4MDUGA1UEBx4uAG4AYwBhAGMAbgBfAG4AcAA6ADEAOQAyAC4AMQA2ADgALgAx
ADMANQAuADMAMDBDBgNVBAUePAAxAEIAYwBLAGUAYQBiADcAWABPAGoAbgBXAEUATQBuAHgAMQBw
AFMAaQA2AEoAUgBBAHUAMAA9AA0ACjBYMAkGBSsOAwIPBQADSwAwSAJBANGDkkicUIVwIX2apm1b
U9WXVMnVT+S081PVP87vGp6VtzYpT9cMNKv70Qi2U3MQoQ4MuKS1XN2uc9SrNC7RWoUCAwEAAaOC
Ac8wggHLMBQGCSsGAQQBgjcSBAEB/wQEAQAFADA8BgkrBgEEAYI3EgIBAf8ELE0AaQBjAHIAbwBz
AG8AZgB0ACAAQwBvAHIAcABvAHIAYQB0AGkAbwBuAAAAMIHNBgkrBgEEAYI3EgUBAf8EgbwAMAAA
AQAAAAIAAAAJBAAAHABKAGYASgCwAAEAMwBkADIANgA3ADkANQA0AC0AZQBlAGIANwAtADEAMQBk
ADEALQBiADkANABlAC0AMAAwAGMAMAA0AGYAYQAzADAAOAAwAGQAAAAzAGQAMgA2ADcAOQA1ADQA
LQBlAGUAYgA3AC0AMQAxAGQAMQAtAGIAOQA0AGUALQAwADAAYwAwADQAZgBhADMAMAA4ADAAZAAA
AAAAABAAgOQAAAAAADB0BgkrBgEEAYI3EgYBAf8EZAAwAAAAABgASABWAFMASQAtAFMAUgBWAC0A
MAAwADQAAAA1ADUAMAA0ADEALQAwADAAOAAtADIAOQAxADMAMwA5ADEALQA4ADQANgAwADkAAABT
AEkAUgBBAEQARQBMAAAAAAAwLwYDVR0jAQH/BCUwI6EapBhWAFMASQAtAFMAUgBWAC0AMAAwADQA
AACCBQEAAAAYMAkGBSsOAwIdBQADggEBAGFI8teU2iypPG2BbpNLa+zZeb87MNjtzHgQlC0RfoK0
dY91t3OXA5pdyD5IRRkvGUVKBf/5G/OVZZvKTnyh3daopD6InPy1X6Wlx5QveCL8ydd/H+ezm0zl
KlMg0pImG0V2NX50q4b9R4I5xiaA7mUeww6rz6iAh1iB2CYHOc/uGAS1/PPtHqnfss5bY+wZR+tW
dvyMFvn6DbvzAN9wT2KIcv1LtMGgxv28v+dnqGhcxrLRE4nRjMIV/AKpBJXhgH7DaUEc1NJNDPUt
5Pdz4qy8WM2d8JO0yNXQVqykJahgt5TJxCoP46SPFUU5XBbNTZuKv7CtPkSxgtrdrzwFTtcAAAAA
AAAAAAAAAAAAAAAAAQAAAA4ADgBtaWNyb3NvZnQuY29tAA==
"""

class TestLic(unittest.TestCase):
    """
    @summary: Test case for MCS automata
    """
    
    class LIC_PASS(Exception):
        """
        @summary: for OK tests
        """
        pass
    
    class LIC_FAIL(Exception):
        """
        @summary: for KO tests
        """
        pass
    
    def test_valid_client_licensing_error_message(self):
        l = lic.LicenseManager(None)
        s = type.StringStream()
        s.writeType(lic.createValidClientLicensingErrorMessage())
        #reinit position
        s.pos = 0
        
        self.assertTrue(l.recv(s), "Manager can retrieve valid case")
        
    def test_new_license(self):
        class Transport(object):
            def __init__(self):
                self._state = False
            def sendFlagged(self, flag, message):
                if flag != sec.SecurityFlag.SEC_LICENSE_PKT:
                    return
                s = type.StringStream()
                s.writeType(message)
                s.pos = 0
                s.readType(lic.LicPacket(lic.ClientNewLicenseRequest()))
                self._state = True
            def getGCCServerSettings(self):
                class A:
                    def __init__(self):
                        self._is_readed = False
                class B:
                    def __init__(self):
                        self.serverCertificate = A()
                class C:
                    def __init__(self):
                        self.SC_SECURITY = B()
                return C()
        
        t = Transport()
        l = lic.LicenseManager(t)
        
        s = type.StringStream(SERVERREQUEST.decode("base64"))
        
        self.assertFalse(l.recv(s) and t._state, "Bad message after license request")