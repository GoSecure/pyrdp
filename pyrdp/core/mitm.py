#
# This file is part of the PyRDP project.
# Copyright (C) 2020-2023 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import logging
import random

from twisted.internet.protocol import ServerFactory
import namesgenerator

from pyrdp.mitm import MITMConfig, RDPMITM
from pyrdp.logging import LOGGER_NAMES, SessionLogger


class MITMServerFactory(ServerFactory):
    """
    Server factory for the RDP man-in-the-middle that generates a unique session ID for every connection.
    """

    def __init__(self, config: MITMConfig):
        """
        :param config: the MITM configuration
        """
        self.config = config

    def buildProtocol(self, addr):
        sessionID = f"{namesgenerator.get_random_name()}_{random.randrange(1000000,9999999)}"

        # mainLogger logs in a file and stdout
        mainlogger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
        mainlogger = SessionLogger(mainlogger, sessionID)

        # crawler logger only logs to a file for analysis purposes
        crawlerLogger = logging.getLogger(LOGGER_NAMES.CRAWLER)
        crawlerLogger = SessionLogger(crawlerLogger, sessionID)

        mitm = RDPMITM(mainlogger, crawlerLogger, self.config)

        return mitm.getProtocol()
