"""
Tests for client fingerprinting functionality (Issue #225)
"""

import unittest
from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE
from pyrdp.enum import ConnectionDataType
from pyrdp.parser import ClientConnectionParser
from pyrdp.pdu import ClientMonitorData, ClientMonitorDefinition


class TestClientMonitorData(unittest.TestCase):
    """Test parsing and writing of TS_UD_CS_MONITOR structure"""

    def test_parse_single_monitor(self):
        """Test parsing client monitor data with single monitor"""
        # Build test data according to MS-RDPBCGR 2.2.1.3.6
        stream = BytesIO()

        # flags: 0
        Uint32LE.pack(0, stream)
        # monitorCount: 1
        Uint32LE.pack(1, stream)

        # Monitor definition
        # left, top, right, bottom
        Uint32LE.pack(0, stream)
        Uint32LE.pack(0, stream)
        Uint32LE.pack(1920, stream)
        Uint32LE.pack(1080, stream)
        # flags: TS_MONITOR_PRIMARY (0x00000001)
        Uint32LE.pack(1, stream)

        data = stream.getvalue()
        parser = ClientConnectionParser()

        monitor_data = parser.parseClientMonitorData(BytesIO(data))

        self.assertEqual(monitor_data.flags, 0)
        self.assertEqual(monitor_data.monitorCount, 1)
        self.assertEqual(len(monitor_data.monitors), 1)

        monitor = monitor_data.monitors[0]
        self.assertEqual(monitor.left, 0)
        self.assertEqual(monitor.top, 0)
        self.assertEqual(monitor.right, 1920)
        self.assertEqual(monitor.bottom, 1080)
        self.assertEqual(monitor.flags, 1)

    def test_parse_multiple_monitors(self):
        """Test parsing client monitor data with multiple monitors"""
        stream = BytesIO()

        # flags: 0
        Uint32LE.pack(0, stream)
        # monitorCount: 2
        Uint32LE.pack(2, stream)

        # Monitor 1: Primary
        Uint32LE.pack(0, stream)
        Uint32LE.pack(0, stream)
        Uint32LE.pack(1920, stream)
        Uint32LE.pack(1080, stream)
        Uint32LE.pack(1, stream)  # Primary

        # Monitor 2: Secondary
        Uint32LE.pack(1920, stream)
        Uint32LE.pack(0, stream)
        Uint32LE.pack(3840, stream)
        Uint32LE.pack(1080, stream)
        Uint32LE.pack(0, stream)  # Not primary

        data = stream.getvalue()
        parser = ClientConnectionParser()

        monitor_data = parser.parseClientMonitorData(BytesIO(data))

        self.assertEqual(monitor_data.monitorCount, 2)
        self.assertEqual(len(monitor_data.monitors), 2)

        # Check monitor 1
        self.assertEqual(monitor_data.monitors[0].right, 1920)
        self.assertEqual(monitor_data.monitors[0].flags, 1)

        # Check monitor 2
        self.assertEqual(monitor_data.monitors[1].left, 1920)
        self.assertEqual(monitor_data.monitors[1].right, 3840)
        self.assertEqual(monitor_data.monitors[1].flags, 0)

    def test_write_single_monitor(self):
        """Test writing client monitor data"""
        # Create monitor data
        monitor = ClientMonitorDefinition(0, 0, 1920, 1080, 1)
        monitor_data = ClientMonitorData(0, [monitor])

        parser = ClientConnectionParser()
        data = parser.writeClientMonitorData(monitor_data)

        # Parse it back
        reparsed = parser.parseClientMonitorData(BytesIO(data))

        self.assertEqual(reparsed.flags, 0)
        self.assertEqual(reparsed.monitorCount, 1)
        self.assertEqual(reparsed.monitors[0].left, 0)
        self.assertEqual(reparsed.monitors[0].right, 1920)
        self.assertEqual(reparsed.monitors[0].bottom, 1080)

    def test_parse_extended_data(self):
        """Test parsing monitor extended data (TS_MONITOR_ATTRIBUTES)"""
        stream = BytesIO()

        # flags: 0
        Uint32LE.pack(0, stream)
        # monitorCount: 1
        Uint32LE.pack(1, stream)

        # Monitor definition
        Uint32LE.pack(0, stream)
        Uint32LE.pack(0, stream)
        Uint32LE.pack(1920, stream)
        Uint32LE.pack(1080, stream)
        Uint32LE.pack(1, stream)

        # monitorAttributesSize: 20 bytes
        Uint32LE.pack(20, stream)
        # monitorCount: 1
        Uint32LE.pack(1, stream)

        # TS_MONITOR_ATTRIBUTES
        # physicalWidth: 520mm
        Uint32LE.pack(520, stream)
        # physicalHeight: 290mm
        Uint32LE.pack(290, stream)
        # orientation: ORIENTATION_LANDSCAPE (0)
        Uint32LE.pack(0, stream)
        # desktopScaleFactor: 100 (scale * 100)
        Uint32LE.pack(100, stream)
        # deviceScaleFactor: 100
        Uint32LE.pack(100, stream)

        data = stream.getvalue()
        parser = ClientConnectionParser()

        monitor_data = parser.parseClientMonitorData(BytesIO(data))

        self.assertEqual(monitor_data.monitorCount, 1)
        self.assertIsNotNone(monitor_data.monitorAttributeSize)
        self.assertEqual(monitor_data.monitorAttributeSize, 20)
        self.assertEqual(len(monitor_data.monitorAttributes), 1)

        attrs = monitor_data.monitorAttributes[0]
        self.assertEqual(attrs.physicalWidth, 520)
        self.assertEqual(attrs.physicalHeight, 290)
        self.assertEqual(attrs.orientation, 0)
        self.assertEqual(attrs.desktopScaleFactor, 100)
        self.assertEqual(attrs.deviceScaleFactor, 100)


class TestClientFingerprintLogging(unittest.TestCase):
    """Test that fingerprinting data is properly logged"""

    def test_core_data_has_physical_dimensions(self):
        """Test that ClientCoreData includes physical dimensions"""
        from pyrdp.pdu import ClientCoreData
        from pyrdp.enum import RDPVersion, ColorDepth, KeyboardType

        core = ClientCoreData(
            RDPVersion.RDP5, 1920, 1080, ColorDepth.RNS_UD_COLOR_8BPP,
            0xAA03, 0, 2600, "TEST-PC", KeyboardType.IBM_ENHANCED, 0, 12, b"\x00" * 64
        )

        # Set optional extended fields
        core.desktopPhysicalWidth = 520
        core.desktopPhysicalHeight = 290
        core.desktopOrientation = 0
        core.desktopScaleFactor = 100
        core.deviceScaleFactor = 100

        self.assertEqual(core.desktopPhysicalWidth, 520)
        self.assertEqual(core.desktopPhysicalHeight, 290)
        self.assertEqual(core.desktopOrientation, 0)
        self.assertEqual(core.desktopScaleFactor, 100)
        self.assertEqual(core.deviceScaleFactor, 100)

    def test_parse_core_data_with_extended_fields(self):
        """Test parsing ClientCoreData with physical dimensions"""
        from pyrdp.core import encodeUTF16LE, Uint8
        from pyrdp.enum import RDPVersion, ColorDepth, ConnectionType, DesktopOrientation

        stream = BytesIO()

        # Required fields (128 bytes)
        Uint32LE.pack(RDPVersion.RDP5, stream)
        Uint16LE.pack(1920, stream)  # desktopWidth
        Uint16LE.pack(1080, stream)  # desktopHeight
        Uint16LE.pack(ColorDepth.RNS_UD_COLOR_8BPP, stream)
        Uint16LE.pack(0xAA03, stream)  # sasSequence
        Uint32LE.pack(0, stream)  # keyboardLayout
        Uint32LE.pack(2600, stream)  # clientBuild
        stream.write(encodeUTF16LE("TEST-PC\x00").ljust(32, b'\x00'))  # clientName
        Uint32LE.pack(4, stream)  # keyboardType
        Uint32LE.pack(0, stream)  # keyboardSubType
        Uint32LE.pack(12, stream)  # keyboardFunctionKey
        stream.write(b"\x00" * 64)  # imeFileName

        # Optional fields
        Uint16LE.pack(ColorDepth.RNS_UD_COLOR_8BPP, stream)  # postBeta2ColorDepth
        Uint16LE.pack(1, stream)  # clientProductId
        Uint32LE.pack(0, stream)  # serialNumber
        Uint16LE.pack(16, stream)  # highColorDepth
        Uint16LE.pack(1, stream)  # supportedColorDepths
        Uint16LE.pack(1, stream)  # earlyCapabilityFlags
        stream.write(encodeUTF16LE("\x00" * 32))  # clientDigProductId
        Uint8.pack(0, stream)  # connectionType
        stream.write(b"\x00")  # padding
        Uint32LE.pack(0, stream)  # serverSelectedProtocol

        # Extended physical dimensions
        Uint32LE.pack(520, stream)  # desktopPhysicalWidth
        Uint32LE.pack(290, stream)  # desktopPhysicalHeight
        Uint16LE.pack(DesktopOrientation.ORIENTATION_LANDSCAPE, stream)  # desktopOrientation
        Uint32LE.pack(100, stream)  # desktopScaleFactor
        Uint32LE.pack(100, stream)  # deviceScaleFactor

        data = stream.getvalue()
        parser = ClientConnectionParser()

        core = parser.parseClientCoreData(BytesIO(data))

        self.assertEqual(core.desktopWidth, 1920)
        self.assertEqual(core.desktopHeight, 1080)
        self.assertEqual(core.desktopPhysicalWidth, 520)
        self.assertEqual(core.desktopPhysicalHeight, 290)
        self.assertEqual(core.desktopOrientation, DesktopOrientation.ORIENTATION_LANDSCAPE)
        self.assertEqual(core.desktopScaleFactor, 100)
        self.assertEqual(core.deviceScaleFactor, 100)


if __name__ == '__main__':
    unittest.main()
