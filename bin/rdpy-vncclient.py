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
example of use rdpy as VNC client
"""
import logging
import sys, os, getopt
from PyQt4 import QtGui
from rdpy.ui.qt4 import RFBClientQt
from rdpy.protocol.rfb import rfb

import rdpy.core.log as log
# Sets the log level for the RDPY library ("rdpy").
log.get_logger().setLevel(logging.INFO)
        
class RFBClientQtFactory(rfb.ClientFactory):
    """
    @summary: Factory create a VNC GUI client
    """
    def __init__(self, password):
        """
        @param password: password for VNC authentication
        """
        self._password = password
        
    def buildObserver(self, controller, addr):
        """
        @summary: Build RFB Client observer
        @param controller: build by factory
        @param addr: destination
        """
        #set password
        controller.setPassword(self._password)
        #create client observer
        client = RFBClientQt(controller)
        #create qt widget
        self._w = client.getWidget()
        self._w.setWindowTitle('rdpy-vncclient')
        self._w.show()
        return client
        
    def clientConnectionLost(self, connector, reason):
        """
        @summary: Connection lost event
        @param connector: twisted connector use for vnc connection (use reconnect to restart connection)
        @param reason: str use to advertise reason of lost connection
        """
        QtGui.QMessageBox.warning(self._w, "Warning", "Lost connection : %s"%reason)
        reactor.stop()
        app.exit()
        
    def clientConnectionFailed(self, connector, reason):
        """
        @summary: Connection failed event
        @param connector: twisted connector use for vnc connection (use reconnect to restart connection)
        @param reason: str use to advertise reason of lost connection
        """
        QtGui.QMessageBox.warning(self._w, "Warning", "Connection failed : %s"%reason)
        reactor.stop()
        app.exit()
        
if __name__ == '__main__':
    
    #default script argument
    password = ""
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:")
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
        elif opt == "-p":
            password = arg
            
    if ':' in args[0]:
        ip, port = args[0].split(':')
    else:
        ip, port = args[0], "5900"
        
    #create application
    app = QtGui.QApplication(sys.argv)
    
    #add qt4 reactor
    import qt4reactor
    qt4reactor.install()

    from twisted.internet import reactor
    reactor.connectTCP(ip, int(port), RFBClientQtFactory(password))
    reactor.runReturn()
    app.exec_()