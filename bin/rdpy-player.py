import argparse
import logging
import logging.handlers
import os
import sys

import notify2
from PyQt4.QtGui import QApplication

from rdpy.core import log
from rdpy.player.player import MainWindow


class NotifyHandler(logging.StreamHandler):
    """
    Logging handler that sends desktop (OS) notifications.
    """

    def __init__(self):
        notify2.init("rdpy-player")
        super(NotifyHandler, self).__init__()

    def emit(self, record):
        """
        Sends a notification to the OS to display.
        :param record: the LogRecord object
        """
        notification = notify2.Notification(record.getMessage())
        notification.show()


def prepare_loggers():
    """
    Sets up the "liveplayer" and "liveplayer.ui" loggers to print messages and send notifications on connect.
    """
    if not os.path.exists("log"):
        os.makedirs("log")

    liveplayer_logger = logging.getLogger("liveplayer")
    liveplayer_logger.setLevel(logging.DEBUG)

    liveplayer_ui_logger = logging.getLogger("liveplayer.ui")
    liveplayer_ui_logger.setLevel(logging.INFO)

    formatter = logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")

    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler("log/liveplayer.log")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    liveplayer_logger.addHandler(stream_handler)
    liveplayer_logger.addHandler(file_handler)

    notify_handler = NotifyHandler()
    notify_handler.setFormatter(logging.Formatter("[%(asctime)s] - %(message)s"))
    liveplayer_ui_logger.addHandler(notify_handler)


def main():
    """
    Parse the provided command line arguments and launch the GUI.
    :return: The app exit code (0 for normal exit, non-zero for errors)
    """
    log.get_logger().setLevel(logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bind", help="Bind address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Bind port (default: 3000)", default=3000)
    parser.add_argument("-d", "--directory", help="Directory that contains replay files to open.")
    parser.add_argument("-f", "--file", help="replay file to open.")

    arguments = parser.parse_args()

    files_to_read = []
    if arguments.file is not None:
        files_to_read.append(arguments.file)
    if arguments.directory is not None:
        if not arguments.directory.endswith("/"):
            arguments.directory += "/"
        files = filter(lambda file_name: file_name.endswith(".rdpy"), os.listdir(arguments.directory))
        files = map(lambda file_name: arguments.directory + file_name, files)
        files_to_read += files

    app = QApplication(sys.argv)

    mainWindow = MainWindow(arguments.bind, int(arguments.port), files_to_read)
    mainWindow.show()

    return app.exec_()


if __name__ == '__main__':
    prepare_loggers()
    mlog = logging.getLogger("liveplayer")
    ulog = logging.getLogger("liveplayer.ui")
    sys.exit(main())
