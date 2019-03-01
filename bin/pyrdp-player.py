#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio

from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())

from pathlib import Path
import argparse
import logging
import logging.handlers
import sys

from PyQt4.QtGui import QApplication

from pyrdp.logging import LOGGER_NAMES, NotifyHandler
from pyrdp.player import MainWindow


def prepareLoggers(logLevel: int, outDir: Path):
    logDir = outDir / "logs"
    logDir.mkdir(exist_ok = True)

    textFormatter = logging.Formatter("[{asctime}] - {levelname} - {name} - {message}", style = "{")
    notificationFormatter = logging.Formatter("[{asctime}] - {message}", style = "{")

    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(textFormatter)

    fileHandler = logging.handlers.RotatingFileHandler(logDir / "player.log")
    fileHandler.setFormatter(textFormatter)

    pyrdpLogger = logging.getLogger(LOGGER_NAMES.PYRDP)
    pyrdpLogger.addHandler(streamHandler)
    pyrdpLogger.addHandler(fileHandler)
    pyrdpLogger.setLevel(logLevel)

    notifyHandler = NotifyHandler()
    notifyHandler.setFormatter(notificationFormatter)

    uiLogger = logging.getLogger(LOGGER_NAMES.PLAYER_UI)
    uiLogger.addHandler(notifyHandler)


def main():
    """
    Parse the provided command line arguments and launch the GUI.
    :return: The app exit code (0 for normal exit, non-zero for errors)
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("replay", help="Replay files to open on launch (optional)", nargs="*")
    parser.add_argument("-b", "--bind", help="Bind address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Bind port (default: 3000)", default=3000)
    parser.add_argument("-o", "--output", help="Output folder", default="pyrdp_output")
    parser.add_argument("-L", "--log-level", help="Log level", default="INFO", choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"], nargs="?")

    args = parser.parse_args()
    outDir = Path(args.output)
    outDir.mkdir(exist_ok = True)

    logLevel = getattr(logging, args.log_level)
    prepareLoggers(logLevel, outDir)

    app = QApplication(sys.argv)
    mainWindow = MainWindow(args.bind, int(args.port), args.replay)
    mainWindow.show()

    return app.exec_()


if __name__ == '__main__':
    sys.exit(main())
