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
RDP Honey pot use Rss scenario file to simulate RDP server
"""

import sys, os, getopt, time

from rdpy.core import log, error, rss
from rdpy.protocol.rdp import rdp
from twisted.internet import reactor

log._LOG_LEVEL = log.Level.INFO

class HoneyPotServer(rdp.RDPServerObserver):
    def __init__(self, controller, rssFileSizeList):
        """
        @param controller: {RDPServerController}
        @param rssFileSizeList: {Tuple} Tuple(Tuple(width, height), rssFilePath)
        """
        rdp.RDPServerObserver.__init__(self, controller)
        self._rssFileSizeList = rssFileSizeList
        self._dx, self._dy = 0, 0
        self._rssFile = None
        
    def onReady(self):
        """
        @summary:  Event use to inform state of server stack
                    First time this event is called is when human client is connected
                    Second time is after color depth nego, because color depth nego
                    restart a connection sequence
        @see: rdp.RDPServerObserver.onReady
        """
        if self._rssFile is None:
            #compute which RSS file to keep
            width, height = self._controller.getScreen()
            size = width * height
            rssFilePath = sorted(self._rssFileSizeList, key = lambda x: abs(x[0][0] * x[0][1] - size))[0][1]
            log.info("select file (%s, %s) -> %s"%(width, height, rssFilePath))
            self._rssFile = rss.createFileReader(rssFilePath)
        
        domain, username, password = self._controller.getCredentials()
        hostname = self._controller.getHostname()
        log.info("""Credentials:
        \tdomain : %s
        \tusername : %s
        \tpassword : %s
        \thostname : %s
        """%(domain, username, password, hostname));
        self.start()
        
    def onClose(self):
        """ HoneyPot """
        
    def onKeyEventScancode(self, code, isPressed, isExtended):
        """ HoneyPot """
    
    def onKeyEventUnicode(self, code, isPressed):
        """ HoneyPot """
        
    def onPointerEvent(self, x, y, button, isPressed):
        """ HoneyPot """
        
    def start(self):
        self.loopScenario(self._rssFile.nextEvent())
        
    def loopScenario(self, nextEvent):
        """
        @summary: main loop event
        """
        if nextEvent.type.value == rss.EventType.UPDATE:
            self._controller.sendUpdate(nextEvent.event.destLeft.value + self._dx, nextEvent.event.destTop.value + self._dy, nextEvent.event.destRight.value + self._dx, nextEvent.event.destBottom.value + self._dy, nextEvent.event.width.value, nextEvent.event.height.value, nextEvent.event.bpp.value, nextEvent.event.format.value == rss.UpdateFormat.BMP, nextEvent.event.data.value)
            
        elif nextEvent.type.value == rss.EventType.CLOSE:
            self._controller.close()
            return
            
        elif nextEvent.type.value == rss.EventType.SCREEN:
            self._controller.setColorDepth(nextEvent.event.colorDepth.value)
            #compute centering because we cannot resize client
            clientSize = nextEvent.event.width.value, nextEvent.event.height.value
            serverSize = self._controller.getScreen()
            
            self._dx, self._dy = (max(0, serverSize[0] - clientSize[0]) / 2), max(0, (serverSize[1] - clientSize[1]) / 2)
            #restart connection sequence
            return
        
        e = self._rssFile.nextEvent()
        reactor.callLater(float(e.timestamp.value) / 1000.0, lambda:self.loopScenario(e))
        
class HoneyPotServerFactory(rdp.ServerFactory):
    """
    @summary: Factory on listening events
    """
    def __init__(self, rssFileSizeList, privateKeyFilePath, certificateFilePath):
        """
        @param rssFileSizeList: {Tuple} Tuple(Tuple(width, height), rssFilePath)
        @param privateKeyFilePath: {str} file contain server private key (if none -> back to standard RDP security)
        @param certificateFilePath: {str} file contain server certificate (if none -> back to standard RDP security)
        """
        rdp.ServerFactory.__init__(self, 16, privateKeyFilePath, certificateFilePath)
        self._rssFileSizeList = rssFileSizeList
        
    def buildObserver(self, controller, addr):
        """
        @param controller: {rdp.RDPServerController}
        @param addr: destination address
        @see: rdp.ServerFactory.buildObserver
        """
        log.info("Connection from %s:%s"%(addr.host, addr.port))
        return HoneyPotServer(controller, self._rssFileSizeList)
    
def readSize(filePath):
    """
    @summary: read size event in rss file
    @param filePath: path of rss file
    """
    r = rss.createFileReader(filePath)
    while True:
        e = r.nextEvent()
        if e is None:
            return None
        elif e.type.value == rss.EventType.SCREEN:
            return e.event.width.value, e.event.height.value
    
def help():
    """
    @summary: Print help in console
    """
    print """
    Usage:  rdpy-rdphoneypot.py rss_filepath(1..n)
            [-l listen_port default 3389] 
            [-k private_key_file_path (mandatory for SSL)] 
            [-c certificate_file_path (mandatory for SSL)] 
    """
    
if __name__ == '__main__':
    listen = "3389"
    privateKeyFilePath = None
    certificateFilePath = None
    rssFileSizeList = []
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hl:k:c:")
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
        elif opt == "-l":
            listen = arg
        elif opt == "-k":
            privateKeyFilePath = arg
        elif opt == "-c":
            certificateFilePath = arg
    
    #build size map
    log.info("Build size map")
    for arg in args:
        size = readSize(arg)
        rssFileSizeList.append((size, arg))
        log.info("(%s, %s) -> %s"%(size[0], size[1], arg))
    
    reactor.listenTCP(int(listen), HoneyPotServerFactory(rssFileSizeList, privateKeyFilePath, certificateFilePath))
    reactor.run()