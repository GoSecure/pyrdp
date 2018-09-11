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
import sys
import socket

from PyQt4 import QtGui, QtCore

from rdpy.core import log, rss
from rdpy.ui.qt4 import QRemoteDesktop, RDPBitmapToQtImage
from rdpy.ui.event import RSSEventHandler
from rdpy.core.scancode import scancodeToChar
log._LOG_LEVEL = log.Level.INFO

class ReaderThread(QtCore.QThread):
    event_received = QtCore.pyqtSignal(object)
    connection_closed = QtCore.pyqtSignal()

    def __init__(self, reader):
        super(QtCore.QThread, self).__init__()
        self.reader = reader
        self.done = False

    def run(self):
        while not self.done:
            event = self.reader.nextEvent()

            if event is None:
                self.connection_closed.emit()
                break
            else:
                self.event_received.emit(event)

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

class LivePlayerWindow(QtGui.QWidget):
    """
    @summary: main window of rss player
    """

    def __init__(self):
        super(LivePlayerWindow, self).__init__()

        self._write_in_caps = False
        self._viewer = LivePlayerWidget(800, 600)
        self._text = QtGui.QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFixedHeight(150)
        self._handler = RSSEventHandler(self._viewer, self._text)

        scrollViewer = QtGui.QScrollArea()
        scrollViewer.setWidget(self._viewer)
        
        layout = QtGui.QVBoxLayout()
        layout.addWidget(scrollViewer, 1)
        layout.addWidget(self._text, 2)
        
        self.setLayout(layout)
        self.setGeometry(0, 0, 800, 600)

    def start(self, reader):
        self.thread = ReaderThread(reader)
        self.thread.event_received.connect(self._handler.on_event_received)
        self.thread.connection_closed.connect(self.on_connection_closed)
        self.thread.start()
    
    def on_connection_closed(self):
        self.close()
    
    def close_event(self, event):
        self.thread.done = True
        event.accept()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", help="Port to listen to for incoming connections", default=3000)

    args = parser.parse_args()

    #create application
    app = QtGui.QApplication(sys.argv)
    
    mainWindow = LivePlayerWindow()
    mainWindow.show()

    HOST = ""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, int(args.port)))
    server.listen(True)
    sock, addr = server.accept()

    reader = rss.SocketReader(sock)
    mainWindow.start(reader)
    exit_code = app.exec_()
    reader.close()
    server.close()
    sys.exit(exit_code)