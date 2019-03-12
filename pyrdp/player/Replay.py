import os
from collections import defaultdict
from typing import BinaryIO, Dict, List

from pyrdp.layer import PlayerMessageLayer
from pyrdp.pdu import PlayerMessagePDU


class Replay:
    """
    Class containing information on a replay's events.
    """

    def __init__(self, file: BinaryIO):
        self.events: Dict[int, List[int]] = {}

        # Remember the current file position
        startingPosition = file.tell()

        # Get file size
        file.seek(0, os.SEEK_END)
        size = file.tell()

        # Take note of the position of each event and its timestamp
        events = defaultdict(list)
        currentMessagePosition = 0
        file.seek(0)

        # Register PDUs as they are parsed by the layer
        def registerEvent(pdu: PlayerMessagePDU):
            events[pdu.timestamp].append(currentMessagePosition)

        # The layer will take care of parsing for us
        player = PlayerMessageLayer()
        player.createObserver(onPDUReceived = registerEvent)

        # Parse all events in the file
        while file.tell() < size:
            data = file.read(8)
            player.recv(data)

            data = file.read(player.getDataLengthRequired())
            player.recv(data)
            currentMessagePosition = file.tell()

        # Restore original file position
        file.seek(startingPosition)

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