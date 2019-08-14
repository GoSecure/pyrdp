#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
from pathlib import Path

from pyrdp.logging.formatters import SSLSecretFormatter


class LOGGER_NAMES:
    # Root logger
    PYRDP = "pyrdp"
    MITM = f"{PYRDP}.mitm"
    MITM_CONNECTIONS = f"{MITM}.connections"
    PLAYER = f"{PYRDP}.player"
    PLAYER_UI = f"{PLAYER}.ui"

    # Independant logger
    CRAWLER = "crawler"

def getSSLLogger():
    """
    Get the SSL logger.
    """
    return logging.getLogger("ssl")

def prepareSSLLogger(path: Path):
    """
    Prepares the SSL master secret logger.
    Used to log TLS session secrets in a format expected by Wireshark.

    :param path: path where master secrets will be saved.
    """
    formatter = SSLSecretFormatter()

    fileHandler = logging.FileHandler(path)
    fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    logger = getSSLLogger()
    logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)
    logger.setLevel(logging.INFO)

def info(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).info(*args)


def debug(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).debug(*args)


def warning(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).warning(*args)


def error(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).error(*args)
