#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import os
from collections import defaultdict
from typing import BinaryIO, Dict, List, Optional

from pyrdp.core import FilePositionGuard
from pyrdp.layer import PlayerLayer
from pyrdp.pdu import PlayerPDU


class Replay:
    """
    Class containing information on a replay's events.
    """

    def __init__(self, file: BinaryIO):
        self.events: Dict[int, List[int]] = {}
        self.file = file

        # Remember the current file position
        with FilePositionGuard(file):
            # Get file size
            file.seek(0, os.SEEK_END)
            size = file.tell()

            # Take note of the position of each event and its timestamp
            events = defaultdict(list)
            currentMessagePosition = 0
            file.seek(0)

            # Register PDUs as they are parsed by the layer
            def registerEvent(pdu: PlayerPDU):
                nonlocal currentMessagePosition
                events[pdu.timestamp].append(currentMessagePosition)

            # Register the offset of every event in the file.
            player = PlayerLayer()
            player.createObserver(onPDUReceived=registerEvent)

            # Parse all events in the file
            while file.tell() < size:
                data = file.read(8)
                player.recv(data)

                data = file.read(player.getDataLengthRequired())
                player.recv(data)
                currentMessagePosition = file.tell()

        # Use relative timestamps to simplify things
        if len(events) == 0:
            self.duration = 0
        else:
            timestamps = sorted(events.keys())
            referenceTime = timestamps[0]

            for absoluteTimestamp in timestamps:
                relativeTimestamp = absoluteTimestamp - referenceTime
                self.events[relativeTimestamp] = events[absoluteTimestamp]

            self.duration = (timestamps[-1] - referenceTime) / 1000.0

    def __len__(self):
        return len(self.getSortedEvents())

    def __iter__(self):
        return ReplayReader(self)

    def getSortedTimestamps(self):
        return sorted(self.events.keys())

    def getSortedEvents(self):
        """
        Returns a flat list of all events ordered by timestamp.
        """
        return [e for _, events in sorted(self.events.items(), key=lambda pair: pair[0]) for e in events]

    def getEventStream(self):
        """
        Transform events (dict of list, timestamp: [positions], without repetition)
        into an iterable eventStream (list of tuples, [(timestamp, position), ...], with repetition)
        """
        return [(timestamp, pos)
                for timestamp, positions in sorted(self.events.items(), key=lambda pair: pair[0])
                for pos in positions
        ]


class ReplayReader:
    def __init__(self, replay: Replay):
        self.replay = replay
        self.timestamps = self.replay.getSortedTimestamps()
        self.eventPositions = self.replay.getSortedEvents()
        self.eventStream = self.replay.getEventStream()

        self.player = PlayerLayer()
        self.observer = self.player.createObserver(onPDUReceived = lambda: None)
        self.n = 0

    """
    Class used to simplify reading replays.
    """

    def readEvent(self, position: int) -> PlayerPDU:
        event: Optional[PlayerPDU] = None

        # When we feed data to self.player, this function will be called and the event variable will be set
        def onPDUReceived(pdu: PlayerPDU):
            nonlocal event
            event = pdu

        self.observer.onPDUReceived = onPDUReceived

        with FilePositionGuard(self.replay.file):
            self.replay.file.seek(position)
            data = self.replay.file.read(8)
            self.player.recv(data)

            data = self.replay.file.read(self.player.getDataLengthRequired())

            # Parse event
            self.player.recv(data)

        return event

    def __len__(self):
        return len(self.replay)

    def __next__(self):
        if self.n >= len(self.replay):
            raise StopIteration

        timestamp, position = self.eventStream[self.n]
        event = self.readEvent(position)

        self.n += 1
        return event, timestamp
