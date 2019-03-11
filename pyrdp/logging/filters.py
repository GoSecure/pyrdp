#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import Filter, LogRecord


class LoggerNameFilter(Filter):
    """
    Filter object that filters on logger names and supports wildcards (*).
    """

    def __init__(self, name: str):
        super().__init__(name)

    def filter(self, record: LogRecord):
        if self.name == "":
            return True

        filterParts = self.name.split(".")
        loggerParts = record.name.split(".")

        if len(filterParts) > len(loggerParts):
            return False

        for index in range(len(filterParts)):
            filterPart = filterParts[index]
            logPart = loggerParts[index]

            if filterPart != logPart and filterPart != "*":
                return False

        return True


class SensorFilter(Filter):
    """
    Filter that adds the sensor id to the logrecord's arguments.
    """

    def __init__(self, sensorID):
        super().__init__()
        self.sensorID = sensorID

    def filter(self, record: LogRecord) -> bool:
        if record.args == ():
            record.args = {}
        elif isinstance(record.args, dict):
            record.args.update({"sensor": self.sensorID})

        return True


class ConnectionMetadataFilter(Filter):
    """
    Filter that adds arguments to the record regarding the
    active session (such as source IP, port and sessionId)
    """

    def __init__(self, server, sessionId: str):
        super().__init__()
        self.server = server
        self.sessionId = sessionId

    def filter(self, record: LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = {}

        clientInfo = self.server.tcp.transport.client
        record.args.update({
            "src_ip": clientInfo[0],
            "src_port": clientInfo[1],
            "session": self.sessionId
        })

        return True