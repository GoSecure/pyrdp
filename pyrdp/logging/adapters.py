#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging


class SessionLogger(logging.LoggerAdapter):
    """
    Logger adapter that adds a sessionID variable to log messages. Also supports creating child loggers.
    """

    def __init__(self, logger: logging.Logger, sessionID: str):
        """
        Create a new logger adapter with a sessionID variable.
        :param logger: logger to wrap.
        :param sessionID: session ID value.
        """
        super().__init__(logger, {"sessionID": sessionID})

    def createChild(self, childName: str, sessionID: str = None) -> 'SessionLogger':
        """
        Create a child logger wrapped in a SessionLogger.
        :param childName: logger name to append to the current logger's name.
        :param sessionID: the session ID for the child, or None to keep the same session ID.
        :return: a SessionLogger wrapping a logger that inherits the current logger.
        """
        if sessionID is None:
            sessionID = self.extra["sessionID"]

        logger = logging.getLogger(f"{self.name}.{childName}")
        return SessionLogger(logger, sessionID)