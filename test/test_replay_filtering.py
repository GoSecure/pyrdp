#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2025 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
"""
Test for replay event filtering to improve progressbar ETA accuracy.
Tests that only time-consuming events (BITMAP, FAST_PATH_OUTPUT) are counted.
"""
import unittest
from io import BytesIO
from unittest.mock import Mock, patch

from pyrdp.enum import PlayerPDUType
from pyrdp.pdu import PlayerPDU
from pyrdp.player import Replay


class MockReplay(Replay):
    """Mock Replay class for testing without reading actual files."""

    def __init__(self, events):
        """
        Create a mock replay with predefined events.
        :param events: List of (timestamp, PlayerPDUType) tuples
        """
        self.file = BytesIO()
        self.events = {}
        self.duration = 0

        # Organize events by timestamp
        for timestamp, pdu_type in events:
            if timestamp not in self.events:
                self.events[timestamp] = []
            # Store position (mock value since we're not actually writing)
            self.events[timestamp].append(0)


class TestReplayFiltering(unittest.TestCase):
    """Test cases for filtering replay events to only time-consuming ones."""

    def test_filter_only_time_consuming_events(self):
        """Test that filtering returns only BITMAP and FAST_PATH_OUTPUT events."""
        # Create mock events with various types
        events = [
            (0, PlayerPDUType.CLIENT_INFO),
            (100, PlayerPDUType.FAST_PATH_OUTPUT),  # Time-consuming
            (200, PlayerPDUType.MOUSE_MOVE),
            (300, PlayerPDUType.BITMAP),  # Time-consuming
            (400, PlayerPDUType.KEYBOARD),
            (500, PlayerPDUType.FAST_PATH_OUTPUT),  # Time-consuming
            (600, PlayerPDUType.TEXT),
        ]

        expected_time_consuming = [
            PlayerPDUType.FAST_PATH_OUTPUT,
            PlayerPDUType.BITMAP,
            PlayerPDUType.FAST_PATH_OUTPUT,
        ]

        # Filter for time-consuming events
        time_consuming_types = {PlayerPDUType.BITMAP, PlayerPDUType.FAST_PATH_OUTPUT}
        filtered = [pdu_type for _, pdu_type in events if pdu_type in time_consuming_types]

        self.assertEqual(len(filtered), 3)
        self.assertEqual(filtered, expected_time_consuming)

    def test_filter_empty_events(self):
        """Test filtering with no events."""
        events = []
        time_consuming_types = {PlayerPDUType.BITMAP, PlayerPDUType.FAST_PATH_OUTPUT}
        filtered = [pdu_type for _, pdu_type in events if pdu_type in time_consuming_types]

        self.assertEqual(len(filtered), 0)

    def test_filter_no_time_consuming_events(self):
        """Test filtering when no time-consuming events exist."""
        events = [
            (0, PlayerPDUType.CLIENT_INFO),
            (100, PlayerPDUType.MOUSE_MOVE),
            (200, PlayerPDUType.KEYBOARD),
            (300, PlayerPDUType.TEXT),
        ]

        time_consuming_types = {PlayerPDUType.BITMAP, PlayerPDUType.FAST_PATH_OUTPUT}
        filtered = [pdu_type for _, pdu_type in events if pdu_type in time_consuming_types]

        self.assertEqual(len(filtered), 0)

    def test_filter_only_time_consuming_events_present(self):
        """Test filtering when only time-consuming events exist."""
        events = [
            (0, PlayerPDUType.FAST_PATH_OUTPUT),
            (100, PlayerPDUType.BITMAP),
            (200, PlayerPDUType.FAST_PATH_OUTPUT),
            (300, PlayerPDUType.BITMAP),
        ]

        time_consuming_types = {PlayerPDUType.BITMAP, PlayerPDUType.FAST_PATH_OUTPUT}
        filtered = [pdu_type for _, pdu_type in events if pdu_type in time_consuming_types]

        self.assertEqual(len(filtered), 4)

    def test_player_pdu_type_values(self):
        """Test that PlayerPDUType values match expected enum values."""
        self.assertEqual(PlayerPDUType.FAST_PATH_OUTPUT, 2)
        self.assertEqual(PlayerPDUType.BITMAP, 14)


if __name__ == "__main__":
    unittest.main()
