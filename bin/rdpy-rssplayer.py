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
import logging
import sys, os, getopt, socket

from PyQt4 import QtGui, QtCore

from rdpy.core import log, rss
from rdpy.ui.qt4 import QRemoteDesktop, RDPBitmapToQtImage
from rdpy.core.scancode import scancodeToChar
from rdpy.ui.event import RSSEventHandler

# Sets the log level for the RDPY library ("rdpy").
log.get_logger().setLevel(logging.INFO)

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
    def __init__(self, reader):
        super(RssPlayerWindow, self).__init__()
        
        self._viewer = RssPlayerWidget(800, 600)
        self._text = QtGui.QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFixedHeight(150)
        self._reader = reader
        self._handler = RSSEventHandler(self._viewer, self._text)

        scrollViewer = QtGui.QScrollArea()
        scrollViewer.setWidget(self._viewer)
        
        layout = QtGui.QVBoxLayout()
        layout.addWidget(scrollViewer, 1)
        layout.addWidget(self._text, 2)
        
        self.setLayout(layout)
        self.setGeometry(0, 0, 800, 600)
    
    def start(self):
        self.loop(self._reader.nextEvent())

    def loop(self, event):
        """
        @summary: timer function
        @param event: {rdpy.ui.event}
        """

        self._handler.on_event_received(event)
        e = self._reader.nextEvent()
        QtCore.QTimer.singleShot(e.timestamp.value, lambda: self.loop(e))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("rss_file")
    args = parser.parse_args()
    file_path = args.rss_file
    reader = rss.createFileReader(file_path)

    # Create application
    app = QtGui.QApplication(sys.argv)
    mainWindow = RssPlayerWindow(reader)
    mainWindow.show()
    mainWindow.start()
    sys.exit(app.exec_())