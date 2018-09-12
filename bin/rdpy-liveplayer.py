#!/usr/bin/python
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
"""
rss file player
"""
import argparse
import os
import sys
import socket

from PyQt4 import QtGui, QtCore

import notify2

from rdpy.core import log, rss
from rdpy.ui.qt4 import QRemoteDesktop, RDPBitmapToQtImage
from rdpy.ui.event import RSSEventHandler
import logging, logging.handlers
log._LOG_LEVEL = log.Level.INFO


class ReaderThread(QtCore.QThread):
    event_received = QtCore.pyqtSignal(object)
    connection_closed = QtCore.pyqtSignal()

    def __init__(self, sock):
        super(QtCore.QThread, self).__init__()
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


class ServerThread(QtCore.QThread):
    connection_received = QtCore.pyqtSignal(object, object)

    def __init__(self, address, port):
        super(QtCore.QThread, self).__init__()
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
        
        self.server.close()
    
    def stop(self):
        self.done = True


class LivePlayerWidget(QRemoteDesktop):
    """
    @summary: special rss player widget
    """
    def __init__(self, width, height):
        class RssAdaptor(object):
            def sendMouseEvent(self, e, isPressed):
                """ Not Handle """
            def sendKeyEvent(self, e, isPressed):
                """ Not Handle """
            def sendWheelEvent(self, e):
                """ Not Handle """
            def closeEvent(self, e):
                """ Not Handle """
        QRemoteDesktop.__init__(self, width, height, RssAdaptor())


class LivePlayerTab(QtGui.QWidget):
    """
    @summary: main window of rss player
    """

    connection_closed = QtCore.pyqtSignal(object)

    def __init__(self, sock):
        super(LivePlayerTab, self).__init__()
        QtGui.qApp.aboutToQuit.connect(self.handle_close)

        self._write_in_caps = False
        self._viewer = LivePlayerWidget(800, 600)
        self._text = QtGui.QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFixedHeight(150)
        self._handler = RSSEventHandler(self._viewer, self._text)

        self.thread = ReaderThread(sock)
        self.thread.event_received.connect(self._handler.on_event_received)
        self.thread.connection_closed.connect(self.on_connection_closed)
        self.thread.start()

        scrollViewer = QtGui.QScrollArea()
        scrollViewer.setWidget(self._viewer)
        
        layout = QtGui.QVBoxLayout()
        layout.addWidget(scrollViewer, 1)
        layout.addWidget(self._text, 2)
        
        self.setLayout(layout)
        self.setGeometry(0, 0, 800, 600)
    
    def on_connection_closed(self):
        self._text.append("<Connection closed>")
        self.connection_closed.emit(self)
    
    def handle_close(self):
        self.thread.stop()


class LivePlayerWindow(QtGui.QTabWidget):
    def __init__(self, address, port, max_tabs = 5):
        super(LivePlayerWindow, self).__init__()
        QtGui.qApp.aboutToQuit.connect(self.handle_close)

        self._server = ServerThread(address, port)
        self._server.connection_received.connect(self.on_connection_received)
        self._server.start()
        self.max_tabs = max_tabs
        self.setTabsClosable(True)
        self.tabCloseRequested.connect(self.on_tab_closed)
    
    def on_connection_received(self, sock, addr):
        if self.count() >= self.max_tabs:
            return
        ulog.info("RDPY Liveplayer - New connection from {}:{}".format(addr[0], addr[1]))

        tab = LivePlayerTab(sock)
        tab.connection_closed.connect(self.on_connection_closed)
        self.addTab(tab, "%s:%d" % addr)
    
    def on_connection_closed(self, tab):
        index = self.indexOf(tab)
        text = self.tabText(index)
        self.setTabText(index, text + " - Closed")
    
    def on_tab_closed(self, index):
        tab = self.widget(index)
        tab.handle_close()
        self.removeTab(index)
    
    def handle_close(self):
        self._server.stop()


class NotifyHandler(logging.StreamHandler):
    """
        Logging handler that sends desktop (OS) notifications.
    """

    def __init__(self):
        # initialize notify2
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
        Sets up the "liveplayer" logger to print messages and send notifications on connect.
    """
    if not os.path.exists("log"):
        os.makedirs("log")

    liveplayer_logger = logging.getLogger("liveplayer")
    liveplayer_logger.setLevel(logging.DEBUG)

    liveplayer_ui_logger = logging.getLogger("liveplayer.ui")
    liveplayer_ui_logger.setLevel(logging.INFO)

    formatter = logging.Formatter("[%(asctime)s] - LIVEPLAYER - %(levelname)s - %(message)s")

    stream_handler = logging.StreamHandler()
    file_handler = logging.FileHandler("log/liveplayer.log")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    liveplayer_logger.addHandler(stream_handler)
    liveplayer_logger.addHandler(file_handler)

    notify_handler = NotifyHandler()
    notify_handler.setFormatter(logging.Formatter("[%(asctime)s] - %(message)s"))
    liveplayer_ui_logger.addHandler(notify_handler)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bind", help="Bind address (default: 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Bind port (default: 3000)", default=3000)

    args = parser.parse_args()

    prepare_loggers()
    mlog = logging.getLogger("liveplayer")
    ulog = logging.getLogger("liveplayer.ui")

    # create application
    app = QtGui.QApplication(sys.argv)
    
    mainWindow = LivePlayerWindow(args.bind, int(args.port))
    mainWindow.show()

    exit_code = app.exec_()
    sys.exit(exit_code)
