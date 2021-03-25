#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import unittest
from unittest.mock import Mock, MagicMock, patch

from pyrdp.mitm.X224MITM import X224MITM
from pyrdp.parser import NegotiationRequestParser
from pyrdp.pdu import X224ConnectionRequestPDU, NegotiationRequestPDU


class FileMappingTest(unittest.TestCase):
    def setUp(self):
        self.mitm = X224MITM(Mock(), Mock(), Mock(), Mock(), MagicMock(), MagicMock(), MagicMock())

    def test_negotiationFlagsNone_doesntRaise(self):
        connectionRequest = X224ConnectionRequestPDU(0, 0, 0, 0, b"")
        negoRequest = NegotiationRequestPDU(b"", None, None, None, None)

        # Since the module uses a "from import" we need to patch the function in the module we're testing.
        # It won't work if we patch the original module ("pyrdp.core.defer").
        with patch("pyrdp.mitm.X224MITM.defer") as mock_defer, \
                patch.object(NegotiationRequestParser, "parse", return_value=negoRequest) as mock_parse:
            self.mitm.connectToServer = MagicMock()
            self.mitm.onConnectionRequest(connectionRequest)
            self.mitm.connectToServer.assert_called_once()
            mock_defer.assert_called_once()
