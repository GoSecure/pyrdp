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
Join RDPY design with twisted design

RDPY use Layer Protocol design (like twisted)
"""

from rdpy.core.error import CallPureVirtualFuntion

class IStreamListener(object):
    """
    @summary: Interface use to inform stream receiver capability
    """
    def recv(self, s):
        """
        @summary: Signal that data is available
        @param s: Stream
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "recv", "IStreamListener"))
    
class IStreamSender(object):
    """
    @summary: Interface use to inform stream sender capability 
    """
    def send(self, data):
        """
        @summary: Send Stream on layer
        @param data: Type or tuple element handle by transport layer
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "send", "IStreamSender"))
    
class Layer(object):
    """
    @summary:  A simple double linked list with presentation and transport layer
                and a subset of event (connect and close)
    """
    def __init__(self, presentation = None):
        """
        @param presentation: presentation layer
        """
        #presentation layer higher layer in model
        self._presentation = presentation
        #transport layer under layer in model
        self._transport = None
        #auto set transport layer of own presentation layer
        if self._presentation is not None:
            self._presentation._transport = self
    
    def connect(self):
        """
        @summary:  Call when transport layer is connected
                    default is send connect event to presentation layer
        """
        if not self._presentation is None:
            self._presentation.connect()
    
    def close(self):
        """
        @summary:  Close layer event
                    default is sent to transport layer
        """
        if not self._transport is None:
            self._transport.close()
            
class LayerAutomata(Layer, IStreamListener):
    """
    @summary:  Layer with automata callback
                we can set next recv function used for Stream packet
                Usefull for event driven engine as twisted
    """
    def __init__(self, presentation = None):
        """
        @param presentation: presentation Layer
        """
        #call parent constructor
        Layer.__init__(self, presentation)
        
    def setNextState(self, callback = None):
        """
        @summary: Set the next callback in automata
        @param callback: a callable object
        """
        if callback is None:
            callback = lambda x:self.__class__.recv(self, x)
        
        self.recv = callback

#twisted layer concept
from twisted.internet import protocol
from twisted.internet.abstract import FileDescriptor
#first that handle stream     
from type import StringStream

class RawLayerClientFactory(protocol.ClientFactory):
    """
    @summary: Abstract class for Raw layer client factory
    """
    def buildProtocol(self, addr):
        """
        @summary: Function call from twisted
        @param addr: destination address
        """
        rawLayer = self.buildRawLayer(addr)
        rawLayer.setFactory(self)
        return rawLayer
        
    def buildRawLayer(self, addr):
        """
        @summary: Override this function to build raw layer
        @param addr: destination address
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "buildRawLayer", "RawLayerClientFactory"))
    
    def connectionLost(self, rawlayer, reason):
        """
        @summary: Override this method to handle connection lost
        @param rawlayer: rawLayer that cause connectionLost event
        @param reason: twisted reason
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "connectionLost", "RawLayerClientFactory"))
    
class RawLayerServerFactory(protocol.ServerFactory):
    """
    @summary: Abstract class for Raw layer server factory
    """
    def buildProtocol(self, addr):
        """
        @summary: Function call from twisted
        @param addr: destination address
        """
        rawLayer = self.buildRawLayer(addr)
        rawLayer.setFactory(self)
        return rawLayer
    
    def buildRawLayer(self, addr):
        """
        @summary: Override this function to build raw layer
        @param addr: destination address
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "recv", "IStreamListener"))
    
    def connectionLost(self, rawlayer, reason):
        """
        @summary: Override this method to handle connection lost
        @param rawlayer: rawLayer that cause connectionLost event
        @param reason: twisted reason
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "recv", "IStreamListener"))
    

class RawLayer(protocol.Protocol, LayerAutomata, IStreamSender):
    """
    @summary:  Wait event from twisted engine
                And format correct size packet
                And send correct packet to next automata callback
    """
    def __init__(self, presentation = None):
        """
        @param presentation: presentation layer in layer list
        """
        #call parent automata
        LayerAutomata.__init__(self, presentation)
        #data buffer received from twisted network layer
        self._buffer = ""
        #len of next packet pass to next state function
        self._expectedLen = 0
        self._factory = None
        
    def setFactory(self, factory):
        """
        @summary: Call by RawLayer Factory
        @param param: RawLayerClientFactory or RawLayerFactory
        """
        self._factory = factory
        
    def dataReceived(self, data):
        """
        @summary:  Inherit from twisted.protocol class
                    main event of received data
        @param data: string data receive from twisted
        """
        #add in buffer
        self._buffer += data
        #while buffer have expected size call local callback
        while self._expectedLen > 0 and len(self._buffer) >= self._expectedLen:
            #expected data is first expected bytes
            expectedData = StringStream(self._buffer[0:self._expectedLen])
            #rest is for next event of automata
            self._buffer = self._buffer[self._expectedLen:]
            #call recv function
            self.recv(expectedData)
            
    def connectionMade(self):
        """
        @summary: inherit from twisted protocol
        """
        #join two scheme
        self.connect()
        
    def connectionLost(self, reason):
        """
        @summary: Call from twisted engine when protocol is closed
        @param reason: str represent reason of close connection
        """
        self._factory.connectionLost(self, reason)
        
    def getDescriptor(self):
        """
        @return: the twited file descriptor
        """
        return self.transport
        
    def close(self):
        """
        @summary:  Close raw layer
                    Use File descriptor directly to not use TLS close
                    Because is bugged
        """
        FileDescriptor.loseConnection(self.getDescriptor())
            
    def expect(self, expectedLen, callback = None):
        """
        @summary:  Set next automata callback, 
                    But this callback will be only called when
                    data have expectedLen
        @param expectedLen: in bytes length use to call next state
        @param callback: callback call when expected length bytes is received
        """
        self._expectedLen = expectedLen
        #default callback is recv from LayerAutomata
        self.setNextState(callback)
        
    def send(self, message):
        """
        @summary:  Send Stream on TCP layer
                    write rdpy Stream message to str
                    And send it to transport layer
        @param message: (tuple | Type)
        """
        s = StringStream()
        s.writeType(message)
        self.transport.write(s.getvalue())