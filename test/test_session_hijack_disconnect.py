#
# This file is part of the PyRDP project.
# Copyright (C) 2025 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import unittest
from unittest.mock import Mock, MagicMock, patch, call

from pyrdp.mitm.X224MITM import X224MITM
from pyrdp.mitm.AttackerMITM import AttackerMITM
from pyrdp.mitm.state import RDPMITMState
from pyrdp.mitm.config import MITMConfig
from pyrdp.pdu import X224DisconnectRequestPDU, PlayerForwardingStatePDU, PlayerClientStatePDU
from pyrdp.enum.player import PlayerPDUType, ClientState


class SessionHijackDisconnectTest(unittest.TestCase):
    """Test suite for session hijacking with client disconnect handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.config = MITMConfig()
        self.state = RDPMITMState(self.config, "test-session")
        self.client_layer = Mock()
        self.server_layer = Mock()
        self.attacker_layer = Mock()
        self.log = MagicMock()
        self.recorder = Mock()

    def test_client_disconnect_without_hijacking_forwards_to_server(self):
        """When client disconnects without hijacking, disconnect should forward to server"""
        # Setup
        mitm = X224MITM(
            self.client_layer,
            self.server_layer,
            self.log,
            self.state,
            MagicMock(),
            MagicMock(),
            MagicMock()
        )

        disconnect_pdu = X224DisconnectRequestPDU(0, 0, 0, b"")
        self.state.isHijacked = False

        # Execute
        mitm.onClientDisconnectRequest(disconnect_pdu)

        # Assert
        self.server_layer.sendPDU.assert_called_once_with(disconnect_pdu)
        self.assertFalse(self.state.clientConnected)

    def test_client_disconnect_with_hijacking_keeps_server_alive(self):
        """When client disconnects during hijacking, server connection should stay alive"""
        # Setup
        mitm = X224MITM(
            self.client_layer,
            self.server_layer,
            self.log,
            self.state,
            MagicMock(),
            MagicMock(),
            MagicMock()
        )

        disconnect_pdu = X224DisconnectRequestPDU(0, 0, 0, b"")
        self.state.isHijacked = True

        # Execute
        mitm.onClientDisconnectRequest(disconnect_pdu)

        # Assert - server should NOT receive disconnect
        self.server_layer.sendPDU.assert_not_called()
        self.assertFalse(self.state.clientConnected)

    def test_server_disconnect_always_forwards_to_client(self):
        """Server disconnect should always forward to client, even during hijacking"""
        # Setup
        mitm = X224MITM(
            self.client_layer,
            self.server_layer,
            self.log,
            self.state,
            MagicMock(),
            MagicMock(),
            MagicMock()
        )

        disconnect_pdu = X224DisconnectRequestPDU(0, 0, 0, b"")
        self.state.isHijacked = True

        # Execute
        mitm.onServerDisconnectRequest(disconnect_pdu)

        # Assert - client should receive disconnect even during hijacking
        self.client_layer.sendPDU.assert_called_once_with(disconnect_pdu)

    def test_forwarding_state_updates_hijack_status(self):
        """Changing forwarding state should update isHijacked flag"""
        # Setup
        attacker = AttackerMITM(
            Mock(),
            Mock(),
            self.attacker_layer,
            self.log,
            self.state,
            self.recorder
        )

        # Test hijacking starts (both inputs disabled)
        pdu = PlayerForwardingStatePDU(0, forwardInput=False, forwardOutput=False)
        attacker.handleForwardingState(pdu)

        # Assert
        self.assertTrue(self.state.isHijacked)
        self.assertFalse(self.state.forwardInput)
        self.assertFalse(self.state.forwardOutput)

    def test_forwarding_state_release_updates_hijack_status(self):
        """Releasing control should update isHijacked flag"""
        # Setup
        attacker = AttackerMITM(
            Mock(),
            Mock(),
            self.attacker_layer,
            self.log,
            self.state,
            self.recorder
        )

        self.state.isHijacked = True

        # Test hijacking released (inputs enabled)
        pdu = PlayerForwardingStatePDU(0, forwardInput=True, forwardOutput=True)
        attacker.handleForwardingState(pdu)

        # Assert
        self.assertFalse(self.state.isHijacked)
        self.assertTrue(self.state.forwardInput)
        self.assertTrue(self.state.forwardOutput)

    def test_client_state_sent_on_hijack_start(self):
        """Client state should be sent to attacker when hijacking starts"""
        # Setup
        attacker = AttackerMITM(
            Mock(),
            Mock(),
            self.attacker_layer,
            self.log,
            self.state,
            self.recorder
        )

        # Execute - start hijacking
        pdu = PlayerForwardingStatePDU(0, forwardInput=False, forwardOutput=False)
        attacker.handleForwardingState(pdu)

        # Assert - state PDU should be sent
        calls = self.attacker_layer.sendPDU.call_args_list
        self.assertTrue(len(calls) > 0)
        sent_pdu = calls[-1][0][0]
        self.assertEqual(sent_pdu.header, PlayerPDUType.CLIENT_STATE)

    def test_client_state_sent_on_disconnect(self):
        """Client state DISCONNECTED should be sent when client disconnects during hijacking"""
        # Setup
        mitm = X224MITM(
            self.client_layer,
            self.server_layer,
            self.log,
            self.state,
            MagicMock(),
            MagicMock(),
            MagicMock()
        )

        # Inject attacker MITM for state notifications
        self.state.attackerMITM = Mock()

        disconnect_pdu = X224DisconnectRequestPDU(0, 0, 0, b"")
        self.state.isHijacked = True
        self.state.clientConnected = True

        # Execute
        mitm.onClientDisconnectRequest(disconnect_pdu)

        # Assert
        self.state.attackerMITM.notifyClientStateChange.assert_called_once()

    def test_release_control_after_client_disconnect_closes_server(self):
        """Releasing control after client disconnect should close server connection"""
        # Setup
        attacker = AttackerMITM(
            Mock(),
            Mock(),
            self.attacker_layer,
            self.log,
            self.state,
            self.recorder
        )

        # Inject X224 MITM for disconnect handling
        self.state.x224MITM = Mock()

        # Client has disconnected but server is still alive
        self.state.isHijacked = True
        self.state.clientConnected = False

        # Execute - release control
        pdu = PlayerForwardingStatePDU(0, forwardInput=True, forwardOutput=True)
        attacker.handleForwardingState(pdu)

        # Assert - server should be disconnected
        self.state.x224MITM.disconnectServer.assert_called_once()

    def test_initial_client_state_is_idle(self):
        """Initial client state should be IDLE"""
        state = RDPMITMState(self.config, "test-session")

        self.assertEqual(state.clientState, ClientState.IDLE)
        self.assertTrue(state.clientConnected)
        self.assertFalse(state.isHijacked)

    def test_client_state_transitions(self):
        """Test client state transitions through lifecycle"""
        state = RDPMITMState(self.config, "test-session")

        # Initial state
        self.assertEqual(state.clientState, ClientState.IDLE)

        # Client becomes active (e.g., sends input)
        state.clientState = ClientState.ACTIVE
        self.assertEqual(state.clientState, ClientState.ACTIVE)

        # Client disconnects
        state.clientConnected = False
        state.clientState = ClientState.DISCONNECTED
        self.assertEqual(state.clientState, ClientState.DISCONNECTED)


if __name__ == '__main__':
    unittest.main()
