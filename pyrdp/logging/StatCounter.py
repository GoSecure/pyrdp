#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import time
from logging import LoggerAdapter


class STAT:
    """
    Type of statistics that a StatCounter object can hold.
    """

    CONNECTION_TIME = "connectionTime"
    # Duration (in secs) for the TCP connection

    CLIENT_SERVER_RATIO = "clientServerRatio"
    # Ratio of the # of messages coming from the client vs from the server. High value (>1) means high client interaction.

    TOTAL_INPUT = "totalInput"
    # # of messages coming from the client to the server.

    TOTAL_OUTPUT = "totalOutput"
    # # of messages coming from the server to the client.

    IO_INPUT = "input"
    # Packet coming from the client to the server for the io channel

    IO_INPUT_FASTPATH = "fastPathInput"
    # Packet coming from the client to the server for the io channel as a fastpath packet

    IO_INPUT_SLOWPATH = "slowPathInput"
    # Packet coming from the client to the server for the io channel as a slowpath packet

    IO_OUTPUT = "output"
    # Packet coming from the server to the client for the io channel

    IO_OUTPUT_FASTPATH = "fastPathOutput"
    # Packet coming from the server to the client for the io channel as a fastpath packet

    IO_OUTPUT_SLOWPATH = "slowPathOutput"
    # Packet coming from the server to the client for the io channel as a slowpath packet

    MCS = "mcs"
    # Packet Coming from either end for any channel

    MCS_OUTPUT = "mcsOutput"
    # Packet Coming from the server to the client for any channel

    MCS_OUTPUT_ = "mcsOutput_"
    # Packet Coming from the server to the client for a given channel (must append channel # after it)

    MCS_INPUT = "mcsInput"
    # Packet Coming from the client to the server for any channel

    MCS_INPUT_ = "mcsInput_"
    # Packet Coming from the client to the server for a given channel (must append channel # after it)

    VIRTUAL_CHANNEL = "virtualChannel"
    # Packet Coming from either end for any virtual channel that doesnt have a specific implementation (ex clipboard)

    VIRTUAL_CHANNEL_INPUT = "virtualChannelInput"
    # Packet Coming from the client to the server for any virtual channel that doesnt have a specific implementation (ex clipboard)

    VIRTUAL_CHANNEL_OUTPUT = "virtualChannelOutput"
    # Packet Coming from the server to the client for any virtual channel that doesnt have a specific implementation (ex clipboard)

    DEVICE_REDIRECTION = "deviceRedirection"
    # Packet coming from either end for the rdpdr channel

    DEVICE_REDIRECTION_CLIENT = "deviceRedirectionClient"
    # Packet coming from the client to the server for the rdpdr channel

    DEVICE_REDIRECTION_SERVER = "deviceRedirectionServer"
    # Packet coming from the server to the client for the rdpdr channel

    DEVICE_REDIRECTION_IOREQUEST = "deviceRedirectionIORequest"
    # IORequest packets for the rdpdr channel

    DEVICE_REDIRECTION_IORESPONSE = "deviceRedirectionIOResponse"
    # IOResponse packets for the rdpdr channel

    DEVICE_REDIRECTION_IOERROR = "deviceRedirectionIOError"
    # IO error packets for the rdpdr channel

    DEVICE_REDIRECTION_FILE_CLOSE = "deviceRedirectionFileClose"
    # File Close packets for the rdpdr channel

    DEVICE_REDIRECTION_FORGED_FILE_READ = "deviceRedirectionForgedFileRead"
    # File read packets forged by pyrdp for the rdpdr channel

    DEVICE_REDIRECTION_FORGED_DIRECTORY_LISTING = "deviceRedirectionForgedDirectoryListing"
    # Directory listing packets forged by pyrdp for the rdpdr channel

    CLIPBOARD = "clipboard"
    # Number of clipboard PDUs coming from either end

    CLIPBOARD_CLIENT = "clipboardClient"
    # Number of clipboard PDUs coming from the client

    CLIPBOARD_SERVER = "clipboardServer"
    # Number of clipboard PDUs coming from the server

    CLIPBOARD_COPY = "clipboardCopies"
    # Number of times data has been copied by either end

    CLIPBOARD_PASTE = "clipboardPastes"
    # Number of times data has been pasted by either end


class StatCounter:
    """
    Class that keeps track of various statistics during an RDP connection (See STAT)
    """

    def __init__(self):
        self.stats = {"report": 1.0}  # 1.0 = True

    def increment(self, *args: str):
        """
        Increments all statistics passed in arguments
        :param args: list of statistics to increment by one. See STAT for list of allowed values.
        """
        for stat in args:
            if stat not in self.stats:
                self.stats[stat] = 0
            self.stats[stat] += 1

    def incrementWith(self, statDestination: str, *statsSource: str):
        """
        Increments statDestination by all provided statSources
        """
        if statDestination not in self.stats:
            self.stats[statDestination] = 0
        for statSource in statsSource:
            if statSource in self.stats:
                self.stats[statDestination] += self.stats[statSource]

    def start(self):
        """
        Initialize some statistics such as connectionTime
        """
        self.stats[STAT.CONNECTION_TIME] = time.time()

    def stop(self):
        """
        Calculates the last statistics such as interaction ratio and connectionTime
        """
        self.stats[STAT.CONNECTION_TIME] = time.time() - self.stats[STAT.CONNECTION_TIME]
        self.incrementWith(STAT.TOTAL_INPUT, STAT.MCS_INPUT, STAT.IO_INPUT_FASTPATH, STAT.VIRTUAL_CHANNEL_INPUT, STAT.CLIPBOARD_CLIENT, STAT.DEVICE_REDIRECTION_CLIENT)
        self.incrementWith(STAT.TOTAL_OUTPUT, STAT.MCS_OUTPUT, STAT.IO_OUTPUT_FASTPATH, STAT.VIRTUAL_CHANNEL_OUTPUT, STAT.CLIPBOARD_SERVER, STAT.DEVICE_REDIRECTION_SERVER)
        if self.stats[STAT.TOTAL_OUTPUT] > 0:
            self.stats[STAT.CLIENT_SERVER_RATIO] = self.stats[STAT.TOTAL_INPUT] / self.stats[STAT.TOTAL_OUTPUT]

    def logReport(self, log: LoggerAdapter):
        """
        Create an INFO log message to log the Connection report using the keys in self.stats.
        :param log: Logger to use to log the report
        """
        keys = ", ".join([f"{key}: %({key})s" for key in self.stats.keys()])
        log.info(f"Connection report: {keys}", self.stats)
