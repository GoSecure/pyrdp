#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2025 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
"""
Tests for auto-close functionality of disconnected live tabs.
"""
import unittest
from unittest.mock import Mock, MagicMock, patch, call


class TestLiveWindowAutoClose(unittest.TestCase):
    """
    Test auto-close functionality for disconnected live player tabs.
    """

    def test_auto_close_timer_created_on_disconnect(self):
        """Test that a QTimer is created when connection closes."""
        with patch('pyrdp.player.LiveWindow.QTimer') as mock_timer_class:
            from pyrdp.player.LiveWindow import LiveWindow

            # Mock the LiveThread to avoid network operations
            with patch('pyrdp.player.LiveWindow.LiveThread'):
                window = LiveWindow(
                    address='127.0.0.1',
                    port=3389,
                    updateCountSignal=Mock(),
                    options={'autoCloseTimeout': 5000},
                    parent=None
                )

                # Create a mock tab
                tab = Mock()
                window.addTab(tab, "Test Connection")

                # Simulate connection close
                window.onConnectionClosed(tab)

                # Verify QTimer.singleShot was called with correct timeout
                mock_timer_class.singleShot.assert_called()
                call_args = mock_timer_class.singleShot.call_args
                self.assertEqual(call_args[0][0], 5000)  # timeout in ms

    def test_auto_close_disabled_when_timeout_zero(self):
        """Test that auto-close is disabled when timeout is 0."""
        with patch('pyrdp.player.LiveWindow.QTimer') as mock_timer_class:
            from pyrdp.player.LiveWindow import LiveWindow

            with patch('pyrdp.player.LiveWindow.LiveThread'):
                window = LiveWindow(
                    address='127.0.0.1',
                    port=3389,
                    updateCountSignal=Mock(),
                    options={'autoCloseTimeout': 0},
                    parent=None
                )

                tab = Mock()
                window.addTab(tab, "Test Connection")

                # Simulate connection close
                window.onConnectionClosed(tab)

                # QTimer.singleShot should NOT be called
                mock_timer_class.singleShot.assert_not_called()

    def test_default_timeout_value(self):
        """Test that default timeout is 5 seconds."""
        from pyrdp.player.LiveWindow import LiveWindow

        with patch('pyrdp.player.LiveWindow.LiveThread'):
            window = LiveWindow(
                address='127.0.0.1',
                port=3389,
                updateCountSignal=Mock(),
                options={},  # No autoCloseTimeout specified
                parent=None
            )

            # Default should be 5000ms (5 seconds)
            self.assertEqual(window.autoCloseTimeout, 5000)

    def test_auto_close_callback_closes_tab(self):
        """Test that auto-close callback removes the tab."""
        from pyrdp.player.LiveWindow import LiveWindow

        with patch('pyrdp.player.LiveWindow.LiveThread'):
            window = LiveWindow(
                address='127.0.0.1',
                port=3389,
                updateCountSignal=Mock(),
                options={'autoCloseTimeout': 5000},
                parent=None
            )

            tab = Mock()
            window.addTab(tab, "Test Connection")
            initial_count = window.count()

            # Call the auto-close method directly
            window.autoCloseTab(tab)

            # Tab should be removed
            self.assertEqual(window.count(), initial_count - 1)

    def test_auto_close_handles_missing_tab(self):
        """Test that auto-close handles case when tab was already manually closed."""
        from pyrdp.player.LiveWindow import LiveWindow

        with patch('pyrdp.player.LiveWindow.LiveThread'):
            window = LiveWindow(
                address='127.0.0.1',
                port=3389,
                updateCountSignal=Mock(),
                options={'autoCloseTimeout': 5000},
                parent=None
            )

            tab = Mock()
            window.addTab(tab, "Test Connection")
            index = window.indexOf(tab)

            # Manually close tab
            window.removeTab(index)

            # Try to auto-close (should handle gracefully)
            try:
                window.autoCloseTab(tab)
                success = True
            except Exception:
                success = False

            self.assertTrue(success, "autoCloseTab should handle missing tab gracefully")

    def test_closed_tab_text_suffix_added(self):
        """Test that ' - Closed' suffix is added to disconnected tab."""
        from pyrdp.player.LiveWindow import LiveWindow

        with patch('pyrdp.player.LiveWindow.LiveThread'):
            with patch('pyrdp.player.LiveWindow.QTimer'):
                window = LiveWindow(
                    address='127.0.0.1',
                    port=3389,
                    updateCountSignal=Mock(),
                    options={'autoCloseTimeout': 5000},
                    parent=None
                )

                tab = Mock()
                window.addTab(tab, "TestClient")

                # Simulate connection close
                window.onConnectionClosed(tab)

                # Check tab text has closed suffix
                index = window.indexOf(tab)
                tab_text = window.tabText(index)
                self.assertTrue(tab_text.endswith(" - Closed"))


if __name__ == '__main__':
    unittest.main()
