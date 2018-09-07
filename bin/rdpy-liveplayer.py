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

import sys, os, getopt, socket, threading

from PyQt4 import QtGui, QtCore

from rdpy.core import log, rss
from rdpy.ui.qt4 import QRemoteDesktop, RDPBitmapToQtImage
from rdpy.core.scancode import scancodeToChar
log._LOG_LEVEL = log.Level.INFO

class ReaderThread(QtCore.QThread):
    event_received = QtCore.pyqtSignal(object)

    def __init__(self, reader):
        super(QtCore.QThread, self).__init__()
        self.reader = reader
        self.done = False
    
    def run(self):
        while not self.done:
            event = self.reader.nextEvent()
            self.event_received.emit(event)

class RssPlayerWidget(QRemoteDesktop):
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
        
class RssPlayerWindow(QtGui.QWidget):
    """
    @summary: main window of rss player
    """
    def __init__(self):
        super(RssPlayerWindow, self).__init__()
        
        self._viewer = RssPlayerWidget(800, 600)
        self._text = QtGui.QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFixedHeight(150)

        scrollViewer = QtGui.QScrollArea()
        scrollViewer.setWidget(self._viewer)
        
        layout = QtGui.QVBoxLayout()
        layout.addWidget(scrollViewer, 1)
        layout.addWidget(self._text, 2)
        
        self.setLayout(layout)
        
        self.setGeometry(0, 0, 800, 600)
    
    def start(self, reader):
        self.thread = ReaderThread(reader)
        self.thread.event_received.connect(self.on_event_received)
        self.thread.start()
    
    def on_event_received(self, event):
        if event.type.value == rss.EventType.UPDATE:
            image = RDPBitmapToQtImage(event.event.width.value, event.event.height.value, event.event.bpp.value, event.event.format.value == rss.UpdateFormat.BMP, event.event.data.value);
            self._viewer.notifyImage(event.event.destLeft.value, event.event.destTop.value, image, event.event.destRight.value - event.event.destLeft.value + 1, event.event.destBottom.value - event.event.destTop.value + 1)
            
        elif event.type.value == rss.EventType.SCREEN:
            self._viewer.resize(event.event.width.value, event.event.height.value)
            
        elif event.type.value == rss.EventType.INFO:
            self._text.append("Domain : %s\nUsername : %s\nPassword : %s\nHostname : %s\n" % (
                                event.event.domain.value, event.event.username.value, event.event.password.value, event.event.hostname.value))
        elif event.type.value == rss.EventType.KEY_SCANCODE:
            if event.event.isPressed.value == 0:
                self._text.moveCursor(QtGui.QTextCursor.End)
                self._text.insertPlainText(scancodeToChar(event.event.code.value))
            
        elif event.type.value == rss.EventType.CLOSE:
            pass
    
    def close_event(self, event):
        self.thread.done = True
        event.accept()

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h")
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
            
    #create application
    app = QtGui.QApplication(sys.argv)
    
    mainWindow = RssPlayerWindow()
    mainWindow.show()

    HOST = ""
    PORT = 42069
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(True)
    sock, addr = server.accept()

    reader = rss.SocketReader(sock)
    mainWindow.start(reader)
    sys.exit(app.exec_())