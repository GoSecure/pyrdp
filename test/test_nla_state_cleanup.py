#!/usr/bin/env python3
#
# This file is part of the PyRDP project.
# Copyright (C) 2025 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Test for NLA state cleanup to prevent silent connection failures on reconnection.
Addresses issue #465: Silent client-side connection error when resuming a connection.
"""

import unittest
from unittest.mock import Mock, MagicMock, patch
import logging

from pyrdp.security.nla import NLAHandler
from pyrdp.security import NTLMSSPState
from pyrdp.pdu import NTLMSSPNegotiatePDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU
from pyrdp.enum import NTLMSSPMessageType


class NLAStateCleanupTest(unittest.TestCase):
    """Test suite for NLA state cleanup and reconnection handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_sink = Mock()
        self.mock_logger = MagicMock(spec=logging.LoggerAdapter)

    def create_negotiate_message(self):
        """Create a mock NEGOTIATE message."""
        negotiate = NTLMSSPNegotiatePDU()
        negotiate.messageType = NTLMSSPMessageType.NEGOTIATE_MESSAGE
        return negotiate

    def create_challenge_message(self):
        """Create a mock CHALLENGE message."""
        challenge = NTLMSSPChallengePDU(b'\x01\x02\x03\x04\x05\x06\x07\x08')
        challenge.messageType = NTLMSSPMessageType.CHALLENGE_MESSAGE
        challenge.serverChallenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        return challenge

    def create_authenticate_message(self):
        """Create a mock AUTHENTICATE message."""
        auth = Mock(spec=NTLMSSPAuthenticatePDU)
        auth.messageType = NTLMSSPMessageType.AUTHENTICATE_MESSAGE
        auth.user = "testuser"
        auth.domain = "TESTDOMAIN"
        auth.proof = b'\x00' * 16
        auth.response = b'\x00' * 32
        return auth

    def test_fresh_state_initialization(self):
        """Test that a fresh NLA handler initializes state correctly."""
        state = NTLMSSPState()
        handler = NLAHandler(self.mock_sink, state, self.mock_logger)

        self.assertIsNotNone(handler.ntlmSSPState)
        self.assertIsNone(handler.ntlmSSPState.negotiate)
        self.assertIsNone(handler.ntlmSSPState.challenge)
        self.assertIsNone(handler.ntlmSSPState.authenticate)

    def test_stale_state_reset_on_new_negotiate(self):
        """Test that stale state is reset when receiving a new NEGOTIATE message."""
        # Create state with stale data from previous connection
        stale_state = NTLMSSPState()
        stale_state.negotiate = self.create_negotiate_message()
        stale_state.challenge = self.create_challenge_message()
        stale_state.authenticate = self.create_authenticate_message()

        handler = NLAHandler(self.mock_sink, stale_state, self.mock_logger, ntlmCapture=True)

        # Simulate receiving a new NEGOTIATE message
        negotiate_msg = self.create_negotiate_message()
        test_data = b'test_data'

        with patch.object(handler.ntlmSSPParser, 'findMessage', return_value=0):
            with patch.object(handler.ntlmSSPParser, 'parse', return_value=negotiate_msg):
                with patch.object(handler.ntlmSSPParser, 'writeNTLMSSPChallenge', return_value=b'challenge_response'):
                    handler.onUnknownHeader(b'', test_data)

        # After processing new NEGOTIATE, authenticate should be None (reset)
        self.assertIsNotNone(handler.ntlmSSPState.negotiate)
        self.assertIsNotNone(handler.ntlmSSPState.challenge)
        self.assertIsNone(handler.ntlmSSPState.authenticate, "Authenticate should be reset on new negotiation")

    def test_null_state_handling_in_ntlm_capture(self):
        """Test that null state is properly handled in NLA capture mode."""
        # Start with None state
        handler = NLAHandler(self.mock_sink, None, self.mock_logger, ntlmCapture=True)

        negotiate_msg = self.create_negotiate_message()
        test_data = b'test_data'

        with patch.object(handler.ntlmSSPParser, 'findMessage', return_value=0):
            with patch.object(handler.ntlmSSPParser, 'parse', return_value=negotiate_msg):
                with patch.object(handler.ntlmSSPParser, 'writeNTLMSSPChallenge', return_value=b'challenge_response'):
                    # This should not raise an exception
                    handler.onUnknownHeader(b'', test_data)

        # State should be created
        self.assertIsNotNone(handler.ntlmSSPState)
        self.assertIsNotNone(handler.ntlmSSPState.challenge)

    def test_reconnection_scenario(self):
        """Test full reconnection scenario with state cleanup."""
        state = NTLMSSPState()

        # First connection
        handler1 = NLAHandler(self.mock_sink, state, self.mock_logger, ntlmCapture=True, challenge="0102030405060708")
        negotiate1 = self.create_negotiate_message()

        with patch.object(handler1.ntlmSSPParser, 'findMessage', return_value=0):
            with patch.object(handler1.ntlmSSPParser, 'parse', return_value=negotiate1):
                with patch.object(handler1.ntlmSSPParser, 'writeNTLMSSPChallenge', return_value=b'challenge1'):
                    handler1.onUnknownHeader(b'', b'test_data1')

        # Simulate authentication completing
        state.authenticate = self.create_authenticate_message()

        # Second connection (reconnection) with same state object
        handler2 = NLAHandler(self.mock_sink, state, self.mock_logger, ntlmCapture=True, challenge="090a0b0c0d0e0f10")
        negotiate2 = self.create_negotiate_message()

        with patch.object(handler2.ntlmSSPParser, 'findMessage', return_value=0):
            with patch.object(handler2.ntlmSSPParser, 'parse', return_value=negotiate2):
                with patch.object(handler2.ntlmSSPParser, 'writeNTLMSSPChallenge', return_value=b'challenge2'):
                    handler2.onUnknownHeader(b'', b'test_data2')

        # Second connection should have reset authenticate
        self.assertIsNone(handler2.ntlmSSPState.authenticate, "Authenticate should be reset on reconnection")

    def test_authenticate_without_challenge_logs_error(self):
        """Test that receiving AUTHENTICATE without CHALLENGE logs an error."""
        state = NTLMSSPState()
        handler = NLAHandler(self.mock_sink, state, self.mock_logger, ntlmCapture=True)

        # Try to authenticate without challenge
        auth_msg = self.create_authenticate_message()
        test_data = b'auth_data'

        with patch.object(handler.ntlmSSPParser, 'findMessage', return_value=0):
            with patch.object(handler.ntlmSSPParser, 'parse', return_value=auth_msg):
                # This should log an error but not crash
                handler.onUnknownHeader(b'', test_data)

        # Verify error was logged
        self.mock_logger.error.assert_called_once()
        error_msg = self.mock_logger.error.call_args[0][0]
        self.assertIn("AUTHENTICATE", error_msg)
        self.assertIn("CHALLENGE", error_msg)

        # Verify sink.sendBytes was still called (forward the message)
        self.mock_sink.sendBytes.assert_called_with(test_data)

    def test_non_ntlmssp_data_forwarded(self):
        """Test that non-NTLMSSP data is forwarded without processing."""
        state = NTLMSSPState()
        handler = NLAHandler(self.mock_sink, state, self.mock_logger)

        # Send data that doesn't contain NTLMSSP signature
        random_data = b'\x00\x01\x02\x03\x04\x05'

        with patch.object(handler.ntlmSSPParser, 'findMessage', return_value=-1):
            handler.onUnknownHeader(b'', random_data)

        # Should be forwarded unchanged
        self.mock_sink.sendBytes.assert_called_once_with(random_data)

    def test_challenge_message_updates_state(self):
        """Test that CHALLENGE messages update state properly."""
        state = NTLMSSPState()
        handler = NLAHandler(self.mock_sink, state, self.mock_logger)

        challenge_msg = self.create_challenge_message()
        test_data = b'challenge_data'

        with patch.object(handler.ntlmSSPParser, 'findMessage', return_value=0):
            with patch.object(handler.ntlmSSPParser, 'parse', return_value=challenge_msg):
                handler.onUnknownHeader(b'', test_data)

        # State should be updated
        self.assertIsNotNone(handler.ntlmSSPState.challenge)
        self.mock_sink.sendBytes.assert_called_once_with(test_data)


if __name__ == '__main__':
    unittest.main()
