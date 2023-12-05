#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
# Need to install this reactor before importing any other code
# ruff: noqa: E402
import asyncio
import sys
# We need a special asyncio loop on Windows above Python 3.8. See #316
if (sys.platform == "win32" and sys.version_info.major == 3 and sys.version_info.minor >= 8):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from twisted.internet import asyncioreactor
asyncioreactor.install(asyncio.new_event_loop())

from pathlib import Path
import argparse
import logging
import logging.handlers
import os
import sys

from pyrdp.core import settings  # noqa
from pyrdp.logging import LOGGER_NAMES, NotifyHandler, configure as configureLoggers  # noqa
from pyrdp.player import HAS_GUI  # noqa
from pyrdp.player.config import DEFAULTS  # noqa


# Workaround a macOS bug: https://bugreports.qt.io/browse/QTBUG-87014
os.environ['QT_MAC_WANTS_LAYER']='1'
if HAS_GUI:
    from pyrdp.player import MainWindow
    from PySide6.QtWidgets import QApplication


def enableNotifications(logger):
    """Enable notifications if supported."""
    # https://docs.python.org/3/library/os.html
    if os.name != "nt" and sys.platform != "darwin":
        notifyHandler = NotifyHandler()
        notifyHandler.setFormatter(logging.Formatter("[{asctime}] - {message}", style="{"))

        uiLogger = logging.getLogger(LOGGER_NAMES.PLAYER_UI)
        uiLogger.addHandler(notifyHandler)
    else:
        logger.warning("Notifications are not supported on this platform.")


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
    parser.add_argument("-L", "--log-level", help="Log level", default=None,
                        choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"], nargs="?")
    parser.add_argument("-F", "--log-filter",
                        help="Only show logs from this logger name (accepts '*' wildcards)", default=None)
    parser.add_argument("--headless", help="Parse a replay without rendering the user interface.", action="store_true")
    args = parser.parse_args()

    cfg = settings.load(f'{settings.CONFIG_DIR}/player.ini', DEFAULTS)

    # Modify configuration with switches.
    if args.log_level:
        cfg.set('vars', 'level', args.log_level)
    if args.log_filter:
        cfg.set('logs', 'filter', args.log_filter)
    if args.output:
        cfg.set('vars', 'output_dir', args.output)

    outDir = Path(cfg.get('vars', 'output_dir'))
    outDir.mkdir(exist_ok=True)

    configureLoggers(cfg)
    logger = logging.getLogger(LOGGER_NAMES.PYRDP)

    if cfg.getboolean('logs', 'notifications', fallback=False) and not args.headless:
        enableNotifications(logger)

    if not HAS_GUI and not args.headless:
        logger.error('Headless mode is not specified and PySide6 is not installed.'
                     ' Install PySide6 to use the graphical user interface.')
        sys.exit(127)

    if not args.headless:
        app = QApplication(sys.argv)
        mainWindow = MainWindow(args.bind, int(args.port), args.replay)
        mainWindow.showMaximized()
        mainWindow.show()

        return app.exec_()
    else:
        logger.info('Starting PyRDP Player in headless mode.')
        from pyrdp.player import HeadlessEventHandler
        from pyrdp.player.Replay import Replay
        eventHandler = HeadlessEventHandler()

        for replayPath in args.replay:
            eventHandler.output.write(f'== REPLAY FILE: {replayPath}\n')

            with open(replayPath, "rb") as f:
                replay = Replay(f)

                for event, _ in replay:
                    eventHandler.onPDUReceived(event)

            eventHandler.output.write('\n-- END --------------------------------\n')


if __name__ == '__main__':
    sys.exit(main())
