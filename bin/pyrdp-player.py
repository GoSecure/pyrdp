#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2019 GoSecure Inc.
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
import os

try:
    from PySide2.QtWidgets import QApplication
    from pyrdp.player import MainWindow
    HAS_GUI = True
except ModuleNotFoundError:
    HAS_GUI = False

from pyrdp.logging import LOGGER_NAMES, NotifyHandler

def prepareLoggers(logLevel: int, outDir: Path, headless: bool):
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

    if not headless and HAS_GUI:
        # https://docs.python.org/3/library/os.html
        if os.name != "nt":
            try:
                notifyHandler = NotifyHandler()
                notifyHandler.setFormatter(notificationFormatter)

                uiLogger = logging.getLogger(LOGGER_NAMES.PLAYER_UI)
                uiLogger.addHandler(notifyHandler)
            except Exception:
                # No notification daemon or DBus, can't use notifications.
                pass
        else:
            pyrdpLogger.warning("Notifications are not supported for your platform, they will be disabled.")

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
    parser.add_argument("--headless", help="Parse a replay without rendering the user interface.", action="store_true")

    args = parser.parse_args()
    outDir = Path(args.output)
    outDir.mkdir(exist_ok = True)

    logLevel = getattr(logging, args.log_level)
    prepareLoggers(logLevel, outDir, args.headless)

    if not HAS_GUI and not args.headless:
        logging.error('Headless mode is not specified and PySide2 is not installed. Install PySide2 to use the graphical user interface.')
        exit(127)

    if not args.headless:
        app = QApplication(sys.argv)
        mainWindow = MainWindow(args.bind, int(args.port), args.replay)
        mainWindow.show()

        return app.exec_()
    else:
        logging.info('Starting PyRDP Player in headless mode.')
        from pyrdp.player import HeadlessEventHandler
        from pyrdp.player import Replay
        processEvents = HeadlessEventHandler()
        for replay in args.replay:
            processEvents.output.write(f'== REPLAY FILE: {replay}\n')
            fd = open(replay, "rb")
            replay = Replay(fd, handler=processEvents)
            processEvents.output.write('\n-- END --------------------------------\n')


if __name__ == '__main__':
    sys.exit(main())
