#!/usr/bin/python3
#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
import argparse
import errno
import logging
import logging.handlers
import os
import socket
import sys

import notify2
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from rdpy.core import log, rss
from rdpy.ui.event import RSSEventHandler
from rdpy.ui.qt4 import QRemoteDesktop

global qApp  # Here so the linter stops crying :)


# Sets the log level for the RDPY library ("rdpy").
log.get_logger().setLevel(logging.DEBUG)


class ReaderThread(QThread):
    event_received = pyqtSignal(object, name="Event received")
    connection_closed = pyqtSignal(name="Connection closed")

    def __init__(self, sock):
        super(QThread, self).__init__()
        self.reader = rss.SocketReader(sock)
        self.done = False

    def run(self):
        while not self.done:
            event = self.reader.nextEvent()

            if event is None:
                self.connection_closed.emit()
                break
            else:
                self.event_received.emit(event)

        self.reader.close()

    def stop(self):
        self.reader.close()
        self.done = True


class ServerThread(QThread):
    connection_received = pyqtSignal(object, object, name="Connection received")

    def __init__(self, address, port):
        super(QThread, self).__init__()

        self.address = address
        self.port = port
        self.done = False

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.address, self.port))
        self.server.listen(5)
        self.server.settimeout(0.5)
    
    def run(self):
        while not self.done:
            try:
                sock, addr = self.server.accept()
                self.connection_received.emit(sock, addr)
            except socket.timeout:
                pass
            except socket.error as error:
                print(error)
                raise
                if code != errno.EINTR:
                    raise
        
        self.server.close()
    
    def stop(self):
        self.done = True


class LivePlayerWidget(QRemoteDesktop):
    """
    @summary: special rss player widget
    """
    def __init__(self, width, height):
        QRemoteDesktop.__init__(self, width, height, RssAdaptor())


class RssAdaptor(object):
    def sendMouseEvent(self, e, isPressed):
        """ Not Handle """
    def sendKeyEvent(self, e, isPressed):
        """ Not Handle """
    def sendWheelEvent(self, e):
        """ Not Handle """
    def closeEvent(self, e):
        """ Not Handle """


class RDPConnectionTab(QWidget):
    """
    Class that encapsulates logic for a tab that displays a RDP connection, regardless of its provenance
    (ex Network or file)
    """

    def __init__(self, viewer, *args, **kwargs):
        """
        :type viewer: QWidget
        """
        QWidget.__init__(self, None, Qt.WindowFlags())
        qApp.aboutToQuit.connect(self.handle_close)
        self._viewer = viewer
        self.speed_multiplier = 1

        self._write_in_caps = False
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setMinimumHeight(150)
        self._handler = RSSEventHandler(self._viewer, self._text)

        scrollViewer = QScrollArea()
        scrollViewer.setWidget(self._viewer)
        layout = QVBoxLayout()
        layout.addWidget(scrollViewer, 8)
        layout.addWidget(self._text, 2)

        self.setLayout(layout)

    def handle_close(self):
        mlog.debug("Close tab")


class ControlBar(QWidget):
    """
    Control bar displayed at the bottom of the GUI that gives access
    to buttons such as Play, stop and rewind.
    """

    def __init__(self, *args, **kwargs):
        QWidget.__init__(self, None, *args, **kwargs)

        self._play_action = lambda: None
        self._stop_action = lambda: None
        self._rewind_action = lambda: None
        self._slider_change_action = lambda new_value: None
        self.speed_label = QLabel("Speed: 1x")

        layout = QFormLayout()
        play_button = QPushButton("Play")
        stop_button = QPushButton("Pause")
        rewind_button = QPushButton("Restart")
        self.speed_slider = QSlider(Qt.Horizontal)

        play_button.clicked.connect(self.on_play_clicked)
        stop_button.clicked.connect(self.on_stop_clicked)
        rewind_button.clicked.connect(self.on_rewind_clicked)
        self.speed_slider.valueChanged.connect(self.on_slider_change)
        play_button.setMaximumWidth(100)
        stop_button.setMaximumWidth(100)
        rewind_button.setMaximumWidth(100)
        self.speed_slider.setMaximumWidth(300)
        self.speed_slider.setMinimum(1)
        self.speed_slider.setMaximum(10)
        sub_layout = QFormLayout()
        layout.addRow(play_button, sub_layout)
        sub_layout.addRow(stop_button, rewind_button)
        layout.addRow(self.speed_label, self.speed_slider)

        self.setLayout(layout)

        self.setGeometry(0, 0, 80, 60)

    def set_play_action(self, action):
        """
        :type action: Callable
        """
        self._play_action = action

    def set_stop_action(self, action):
        """
        :type action: Callable
        """
        self._stop_action = action

    def set_rewind_action(self, action):
        """
        :type action: Callable
        """
        self._rewind_action = action

    def set_slider_change_action(self, action):
        """
        :type action: Callable
        """
        self._slider_change_action = action

    def on_play_clicked(self):
        mlog.debug("Play clicked")
        self._slider_change_action(self.speed_slider.value())
        self._play_action()

    def on_stop_clicked(self):
        mlog.debug("Stop clicked")
        self._stop_action()

    def on_rewind_clicked(self):
        mlog.debug("Rewind clicked")
        self._rewind_action()

    def on_slider_change(self):
        new_value = self.speed_slider.value()
        mlog.debug("Slider changed value: {}".format(new_value))
        self.speed_label.setText("Speed: {}x".format(new_value))
        self._slider_change_action(new_value)


class LivePlayerTab(RDPConnectionTab):
    """
    Tab playing a live RDP connection as data is being received over the network.
    """

    connection_closed = pyqtSignal(object, name="Close")

    def __init__(self, sock, *args, **kwargs):
        RDPConnectionTab.__init__(self, LivePlayerWidget(1024, 768), None, *args, **kwargs)

        self.thread = ReaderThread(sock)
        self.thread.event_received.connect(self._handler.on_message_received)
        self.thread.connection_closed.connect(self.on_connection_closed)
        self.thread.start()

    def on_connection_closed(self):
        self._text.append("<Connection closed>")
        self.connection_closed.emit(self)

    def handle_close(self):
        self.thread.stop()


class ReplayTabHolder(QWidget):

    def __init__(self, flags, *args, **kwargs):
        QWidget.__init__(self, flags, *args, **kwargs)
        self.replay_tab = None
        layout = QVBoxLayout()
        self.setLayout(layout)

    def set_replay_tab(self, replay_tab):
        """
        Replaces the current replay tab (if any) by a new one.
        :type replay_tab: ReplayTab
        """
        if self.replay_tab is not None:
            self.layout().removeWidget(self.replay_tab)
        self.replay_tab = replay_tab
        self.layout().addWidget(self.replay_tab)

    def handle_close(self):
        """
        Pass the method to the replay tab
        """
        self.replay_tab.handle_close()


class ReplayTab(RDPConnectionTab):
    """
    Tab that displays a RDP Connection that is being replayed from a file.
    """

    def __init__(self, reader, file_name, *args, **kwargs):
        """
        :type reader: rdpy.core.rss.FileReader
        """
        self.file_name = file_name
        self.stopped = True
        self.last_timestamp = 0
        RDPConnectionTab.__init__(self, QRemoteDesktop(800, 600, RssAdaptor()), None, *args, **kwargs)

        self._reader = reader

    def start(self):
        """
        Start the RDP Connection replay
        """
        self.stopped = False
        event = self._reader.nextEvent()

        if event:
            self.last_timestamp = event.timestamp
            self.loop(event, speed_multiplier=self.speed_multiplier)
        else:
            mlog.debug("RSS file ended, replay done.")

    def stop(self):
        """
        Sets a flag to stop the replay on the next event.
        """
        # TODO: Fix stop not quite working
        self.stopped = True

    def reset(self):
        """
        Resets the replay to start it over.
        """
        mlog.debug("Resetting current replay {}".format(self))
        self._reader.reset()
        self._text.setText("")
        self.stop()

    def loop(self, event, speed_multiplier=1):

        if not self.stopped:
            self._handler.on_message_received(event)
            e = self._reader.nextEvent()
            if e is not None:
                time_difference = (event.timestamp - self.last_timestamp)
                self.last_timestamp = event.timestamp
                QTimer.singleShot(time_difference / speed_multiplier,
                                  lambda: self.loop(e, speed_multiplier=self.speed_multiplier))
            else:
                mlog.debug("RSS file ended, replay done.")

    def set_speed_multiplier(self, value):
        self.speed_multiplier = value


class BasePlayerWindow(QTabWidget):
    """
    Class that encapsulate the common logic to manage a QtTabWidget to display RDP connections,
    regardless of their provenance (ex Network or file).
    """

    def __init__(self, max_tabs=250):
        QTabWidget.__init__(self)
        qApp.aboutToQuit.connect(self.handle_close)
        self._shortcut = QShortcut(QKeySequence("Ctrl+W"), self, self.close_current_tab)
        self.max_tabs = max_tabs
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.on_tab_closed)

    def close_current_tab(self):
        if self.count() > 0:
            self.on_tab_closed(self.currentIndex())

    def on_tab_closed(self, index):
        """
        Gracefully closes the tab by calling the handle_close method
        :param index: Index of the closed tab
        """
        tab = self.widget(index)
        tab.handle_close()
        self.removeTab(index)

    def handle_close(self):
        pass

    def on_play_clicked(self):
        log.debug("Play action not implemented")

    def on_stop_clicked(self):
        log.debug("Stop action not implemented")

    def on_rewind_clicked(self):
        mlog.debug("Rewind action not implemented")

    def on_slider_change(self, new_value):
        mlog.debug("Slider change action not implemented")


class ReplaysWindow(BasePlayerWindow):
    """
    Class that holds logic for already recorded RDP sessions (in files) tabs.
    """

    def __init__(self, files_to_read):
        BasePlayerWindow.__init__(self)
        self.files_to_read = files_to_read
        i = 0
        for file_name in files_to_read:
            outer_tab = ReplayTabHolder(None)
            inner_tab = ReplayTab(rss.createFileReader(file_name), file_name)
            outer_tab.set_replay_tab(inner_tab)
            self.addTab(outer_tab, file_name)
            mlog.debug("Loading .rss file {} / {}".format(i, len(files_to_read)))
            i += 1

    def on_play_clicked(self):
        mlog.debug("Start .rss file")
        self.currentWidget().replay_tab.start()

    def on_stop_clicked(self):
        mlog.debug("Stop .rss file")
        self.currentWidget().replay_tab.stop()

    def on_rewind_clicked(self):
        mlog.debug("Rewind: Create new ReplayTab and replace the old one.")
        name = self.currentWidget().replay_tab.file_name
        self.currentWidget().set_replay_tab(ReplayTab(rss.createFileReader(name), name))
        self.currentWidget().replay_tab.start()

    def on_slider_change(self, new_value):
        mlog.debug("Change replay speed to {}".format(new_value))
        self.currentWidget().replay_tab.set_speed_multiplier(new_value)


class LiveConnectionsWindow(BasePlayerWindow):
    """
    Class that holds logic for live player (network RDP connections as they happen) tabs.
    """

    def __init__(self, address, port):
        BasePlayerWindow.__init__(self)

        self._server = ServerThread(address, port)
        self._server.connection_received.connect(self.on_connection_received)
        self._server.start()

    def on_connection_received(self, sock, addr):
        if self.count() >= self.max_tabs:
            return
        ulog.info("RDPY Liveplayer - New connection from {}:{}".format(addr[0], addr[1]))
        os.system("beep")

        tab = LivePlayerTab(sock)
        tab.connection_closed.connect(self.on_connection_closed)
        self.addTab(tab, "%s:%d" % addr)
        self.setCurrentIndex(self.count() - 1)

    def on_connection_closed(self, tab):
        index = self.indexOf(tab)
        text = self.tabText(index)
        self.setTabText(index, text + " - Closed")

    def handle_close(self):
        self._server.stop()


class MainWindow(QWidget):
    """
    Main window that contains every other QWidgets.
    """

    def __init__(self, bind_address, port, files_to_read, *args, **kwargs):

        QWidget.__init__(self, None, *args, **kwargs)
        layout = QVBoxLayout()
        control_bar = ControlBar()
        layout.addWidget(PlayerTypeTabManager(control_bar, bind_address, port, files_to_read), 500)
        layout.addWidget(control_bar, 5, alignment=Qt.AlignBottom)
        self.setLayout(layout)


class PlayerTypeTabManager(QTabWidget):
    """
    Class that manages a tab for each RDP Connection player type (ex Network and file)
    """

    def __init__(self, control_bar, bind_address, port, files_to_read):
        """
        :type control_bar: ControlBar
        :param bind_address: The ip address to which we listen on for connections (str).
        :param port: The port to which we listen on for connections (int).
        :param files_to_read: A list of replay file names.
        """
        QTabWidget.__init__(self)
        self.live_player_subwindow = LiveConnectionsWindow(bind_address, port)
        self.recorded_player_subwindow = ReplaysWindow(files_to_read)
        self.addTab(self.recorded_player_subwindow, "RSS files")
        self.addTab(self.live_player_subwindow, "Live connections")
        control_bar.set_play_action(self.on_play_clicked)
        control_bar.set_stop_action(self.on_stop_clicked)
        control_bar.set_rewind_action(self.on_rewind_clicked)
        control_bar.set_slider_change_action(self.on_slider_change)

    def on_play_clicked(self):
        self.currentWidget().on_play_clicked()

    def on_stop_clicked(self):
        self.currentWidget().on_stop_clicked()

    def on_rewind_clicked(self):
        self.currentWidget().on_rewind_clicked()

    def on_slider_change(self, new_value):
        self.currentWidget().on_slider_change(new_value)


class NotifyHandler(logging.StreamHandler):
    """
        Logging handler that sends desktop (OS) notifications.
    """

    def __init__(self):
        notify2.init("rdpy-liveplayer")
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
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bind", help="Bind address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Bind port (default: 3000)", default=3000)
    parser.add_argument("-d", "--directory", help="Directory that contains .rss files to replay.")
    parser.add_argument("-f", "--file", help=".rss file to replay.")

    arguments = parser.parse_args()

    files_to_read = []
    if arguments.file is not None:
        files_to_read.append(arguments.file)
    if arguments.directory is not None:
        if not arguments.directory.endswith("/"):
            arguments.directory += "/"
        files = filter(lambda file_name: file_name.endswith(".rss"), os.listdir(arguments.directory))
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
