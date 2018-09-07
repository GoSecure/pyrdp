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
Implement Remote FrameBuffer protocol use in VNC client and server
@see: http://www.realvnc.com/docs/rfbproto.pdf

@todo: server side of protocol
@todo: more encoding rectangle
"""

from rdpy.core.layer import RawLayer, RawLayerClientFactory
from rdpy.core.type import UInt8, UInt16Be, UInt32Be, SInt32Be, String, CompositeType
from rdpy.core.error import InvalidValue, CallPureVirtualFuntion
from rdpy.security.pyDes import des
import rdpy.core.log as log

class ProtocolVersion(object):
    """
    @summary: Different protocol version
    """
    UNKNOWN = ""
    RFB003003 = "RFB 003.003\n"
    RFB003007 = "RFB 003.007\n"
    RFB003008 = "RFB 003.008\n"

class SecurityType(object):
    """
    @summary: Security type supported 
    """
    INVALID = 0
    NONE = 1
    VNC = 2

class Pointer(object):
    """
    @summary:  Mouse event code (which button)
                actually in RFB specification only
                three buttons are supported
    """
    BUTTON1 = 0x1
    BUTTON2 = 0x2
    BUTTON3 = 0x4
  
class Encoding(object):
    """
    @summary: Encoding types of FrameBuffer update
    """
    RAW = 0

class ClientToServerMessages(object):
    """
    @summary: Client to server messages types
    """
    PIXEL_FORMAT = 0
    ENCODING = 2
    FRAME_BUFFER_UPDATE_REQUEST = 3
    KEY_EVENT = 4
    POINTER_EVENT = 5
    CUT_TEXT = 6
    
class PixelFormat(CompositeType):
    """
    @summary: Pixel format structure
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.BitsPerPixel = UInt8(32)
        self.Depth = UInt8(24)
        self.BigEndianFlag = UInt8(False)
        self.TrueColorFlag = UInt8(True)
        self.RedMax = UInt16Be(255)
        self.GreenMax = UInt16Be(255)
        self.BlueMax = UInt16Be(255)
        self.RedShift = UInt8(16)
        self.GreenShift = UInt8(8)
        self.BlueShift = UInt8(0)
        self.padding = (UInt16Be(), UInt8())
        
class ServerInit(CompositeType):
    """
    @summary:  Server init structure
                FrameBuffer configuration
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.width = UInt16Be()
        self.height = UInt16Be()
        self.pixelFormat = PixelFormat()
        
class FrameBufferUpdateRequest(CompositeType):
    """
    @summary:  FrameBuffer update request send from client to server
                Incremental means that server send update with a specific
                order, and client must draw orders in same order
    """
    def __init__(self, incremental = False, x = 0, y = 0, width = 0, height = 0):
        CompositeType.__init__(self)
        self.incremental = UInt8(incremental)
        self.x = UInt16Be(x)
        self.y = UInt16Be(y)
        self.width = UInt16Be(width)
        self.height = UInt16Be(height)

    
class Rectangle(CompositeType):
    """
    @summary: Header message of update rectangle
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.x = UInt16Be()
        self.y = UInt16Be()
        self.width = UInt16Be()
        self.height = UInt16Be()
        self.encoding = SInt32Be()
        
class KeyEvent(CompositeType):
    """
    @summary:  Key event structure message
                Use to send a keyboard event
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.downFlag = UInt8(False)
        self.padding = UInt16Be()
        self.key = UInt32Be()
        
class PointerEvent(CompositeType):
    """
    @summary:  Pointer event structure message
                Use to send mouse event
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.mask = UInt8()
        self.x = UInt16Be()
        self.y = UInt16Be()
        
class ClientCutText(CompositeType):
    """
    @summary:  Client cut text message message
                Use to simulate copy paste (ctrl-c ctrl-v) only for text
    """
    def __init__(self, text = ""):
        CompositeType.__init__(self)
        self.padding = (UInt16Be(), UInt8())
        self.size = UInt32Be(len(text))
        self.message = String(text)
        
class ServerCutTextHeader(CompositeType):
    """
    @summary:  Cut text header send from server to client
    """
    def __init__(self):
        CompositeType.__init__(self)
        self.padding = (UInt16Be(), UInt8())
        self.size = UInt32Be()

class RFB(RawLayer):
    """
    @summary: Implement RFB protocol
    """
    def __init__(self, listener):
        """
        @param listener: listener use to inform new orders
        """
        RawLayer.__init__(self)
        #set client listener
        self._clientListener = listener
        #useful for RFB protocol
        self._callbackBody = None
        #protocol version negotiated
        self._version = String(ProtocolVersion.RFB003008)
        #number security launch by server
        self._securityLevel = UInt8(SecurityType.INVALID)
        #shared FrameBuffer client init message
        self._sharedFlag = UInt8(False)
        #server init message
        #which contain FrameBuffer dim and pixel format
        self._serverInit = ServerInit()
        #client pixel format
        self._pixelFormat = PixelFormat()
        #server name
        self._serverName = String()
        #nb rectangle
        self._nbRect = 0
        #current rectangle header
        self._currentRect = Rectangle()
        #for vnc security type
        self._password = '\0' * 8
    
    def expectWithHeader(self, expectedHeaderLen, callbackBody):
        """
        2nd level of waiting event
        read expectedHeaderLen that contain body size
        @param expectedHeaderLen: contains the number of bytes, which body length needs to be encoded
        @param callbackBody: next state use when expected date from expectedHeaderLen
        are received
        """
        self._callbackBody = callbackBody
        self.expect(expectedHeaderLen, self.expectedBody)
    
    def expectedBody(self, data):
        """
        Read header and wait header value to call next state
        @param data: Stream that length are to header length (1|2|4 bytes)
        set next state to callBack body when length read from header
        are received
        """
        bodyLen = None
        if data.len == 1:
            bodyLen = UInt8()
        elif data.len == 2:
            bodyLen = UInt16Be()
        elif data.len == 4:
            bodyLen = UInt32Be()
        else:
            log.error("invalid header length")
            return
        data.readType(bodyLen)
        self.expect(bodyLen.value, self._callbackBody)
        
    def connect(self):
        """
        Call when transport layer connection is made
        in Client mode -> wait protocol version
        """
        self.expect(12, self.recvProtocolVersion)
        
    def readProtocolVersion(self, data):
        """
        Read protocol version
        @param data: Stream may contain protocol version string (ProtocolVersion)
        """
        data.readType(self._version)
        if not self._version.value in [ProtocolVersion.RFB003003, ProtocolVersion.RFB003007, ProtocolVersion.RFB003008]:
            self._version.value = ProtocolVersion.UNKNOWN
    
    def recvProtocolVersion(self, data):
        """
        Read handshake packet 
        If protocol receive from client is unknown
        try best version of protocol version (ProtocolVersion.RFB003008)
        @param data: Stream
        """
        self.readProtocolVersion(data)
        if self._version.value == ProtocolVersion.UNKNOWN:
            log.info("Unknown protocol version %s send 003.008"%data.getvalue())
            #protocol version is unknown try best version we can handle
            self._version.value = ProtocolVersion.RFB003008
        #send same version of 
        self.send(self._version)
        
        #next state read security
        if self._version.value == ProtocolVersion.RFB003003:
            self.expect(4, self.recvSecurityServer)
        else:
            self.expectWithHeader(1, self.recvSecurityList)
    
    def recvSecurityServer(self, data):
        """
        Security handshake for 33 RFB version
        Server imposed security level
        @param data: well formed packet
        """
        #TODO!!!
        pass
        
    def recvSecurityList(self, data):
        """
        Read security list packet send from server to client
        @param data: Stream that contains well formed packet
        """
        securityList = []
        while not data.eof():
            securityElement = UInt8()
            data.readType(securityElement)
            securityList.append(securityElement)
        #select high security level
        for s in securityList:
            if s.value in [SecurityType.NONE, SecurityType.VNC] and s > self._securityLevel:
                self._securityLevel = s
                break
        #send back security level choosen
        self.send(self._securityLevel)
        if self._securityLevel.value == SecurityType.VNC:
            self.expect(16, self.recvVNCChallenge)
        else:
            self.expect(4, self.recvSecurityResult)
    
    def recvVNCChallenge(self, data):
        """
        @summary: receive challenge in VNC authentication case
        @param data: Stream that contain well formed packet 
        """
        key = (self._password + '\0' * 8)[:8]
        newkey = []
        for ki in range(len(key)):
            bsrc = ord(key[ki])
            btgt = 0
            for i in range(8):
                if bsrc & (1 << i):
                    btgt = btgt | (1 << 7-i)
            newkey.append(chr(btgt))

        algo = des(newkey)
        self.send(String(algo.encrypt(data.getvalue())))
        self.expect(4, self.recvSecurityResult)
      
    def recvSecurityResult(self, data):
        """
        Read security result packet
        Use by server to inform connection status of client
        @param data: Stream that contain well formed packet 
        """
        result = UInt32Be()
        data.readType(result)
        if result == UInt32Be(1):
            log.info("Authentification failed")
            if self._version.value == ProtocolVersion.RFB003008:
                self.expectWithHeader(4, self.recvSecurityFailed)
        else:
            log.debug("Authentification OK")
            self.sendClientInit()
        
    def recvSecurityFailed(self, data):
        """
        Send by server to inform reason of why it's refused client
        @param data: Stream that contains well formed packet
        """
        log.info("Security failed cause to %s"%data.getvalue())
        
    def recvServerInit(self, data):
        """
        Read server init packet
        @param data: Stream that contains well formed packet
        """
        data.readType(self._serverInit)
        self.expectWithHeader(4, self.recvServerName)
    
    def recvServerName(self, data):
        """
        @summary: Read server name
        @param data: Stream that contains well formed packet
        """
        data.readType(self._serverName)
        log.info("Server name %s"%str(self._serverName))
        #end of handshake
        #send pixel format
        self.sendPixelFormat(self._pixelFormat)
        #write encoding
        self.sendSetEncoding()
        #request entire zone
        self.sendFramebufferUpdateRequest(False, 0, 0, self._serverInit.width.value, self._serverInit.height.value)
        #now i'm ready to send event
        self._clientListener.onReady()
        self.expect(1, self.recvServerOrder)
        
    def recvServerOrder(self, data):
        """
        @summary:  Read order receive from server
                    Main function for bitmap update from server to client
        @param data: Stream that contains well formed packet
        """
        packetType = UInt8()
        data.readType(packetType)
        if packetType.value == 0:
            self.expect(3, self.recvFrameBufferUpdateHeader)
        elif packetType.value == 2:
            self._clientListener.onBell()
        elif packetType.value == 3:
            self.expect(7, self.recvServerCutTextHeader)
        else:
            log.error("Unknown message type %s"%packetType.value)
        
    def recvFrameBufferUpdateHeader(self, data):
        """
        @summary: Read frame buffer update packet header
        @param data: Stream that contains well formed packet
        """
        #padding
        nbRect = UInt16Be()
        self._nbRect = data.readType((UInt8(), nbRect))
        self._nbRect = nbRect.value
        self.expect(12, self.recvRectHeader)
        
    def recvRectHeader(self, data):
        """
        @summary: Read rectangle header
        @param data: Stream that contains well formed packet
        """
        data.readType(self._currentRect)
        if self._currentRect.encoding.value == Encoding.RAW:
            self.expect(self._currentRect.width.value * self._currentRect.height.value * (self._pixelFormat.BitsPerPixel.value / 8), self.recvRectBody)
    
    def recvRectBody(self, data):
        """
        @summary: Read body of rectangle update
        @param data: Stream that contains well formed packet
        """
        self._clientListener.recvRectangle(self._currentRect, self._pixelFormat, data.getvalue())
           
        self._nbRect -= 1
        #if there is another rect to read
        if self._nbRect == 0:
            #job is finish send a request
            self.sendFramebufferUpdateRequest(True, 0, 0, self._serverInit.width.value, self._serverInit.height.value)
            self.expect(1, self.recvServerOrder)
        else:
            self.expect(12, self.recvRectHeader)
            
    def recvServerCutTextHeader(self, data):
        """
        @summary:  callback when expect server cut text message
        @param data: Stream that contains well formed packet
        """
        header = ServerCutTextHeader()
        data.readType(header)
        self.expect(header.size.value, self.recvServerCutTextBody)
        
    def recvServerCutTextBody(self, data):
        """
        @summary:  Receive server cut text body
        @param data: Stream that contains well formed packet
        """
        self._clientListener.onCutText(data.getvalue())
        self.expect(1, self.recvServerOrder)
        
    def sendClientInit(self):
        """
        @summary: Send client init packet
        """
        self.send(self._sharedFlag)
        self.expect(20, self.recvServerInit)
        
    def sendPixelFormat(self, pixelFormat):
        """
        @summary:  Send pixel format structure
                    Very important packet that inform the image struct supported by the client
        @param pixelFormat: PixelFormat struct
        """
        self.send((UInt8(ClientToServerMessages.PIXEL_FORMAT), UInt16Be(), UInt8(), pixelFormat))
        
    def sendSetEncoding(self):
        """
        @summary:  Send set encoding packet
                    Actually only RAW bitmap encoding are used
        """
        self.send((UInt8(ClientToServerMessages.ENCODING), UInt8(), UInt16Be(1), SInt32Be(Encoding.RAW)))
        
    def sendFramebufferUpdateRequest(self, incremental, x, y, width, height):
        """
        @summary:  Request server the specified zone
                    incremental means request only change before last update
        """
        self.send((UInt8(ClientToServerMessages.FRAME_BUFFER_UPDATE_REQUEST), FrameBufferUpdateRequest(incremental, x, y, width, height)))
        
    def sendKeyEvent(self, keyEvent):
        """
        @summary: Write key event packet
        @param keyEvent: KeyEvent struct to send
        """
        self.send((UInt8(ClientToServerMessages.KEY_EVENT), keyEvent))
        
    def sendPointerEvent(self, pointerEvent):
        """
        @summary: Write pointer event packet
        @param pointerEvent: PointerEvent struct use
        """
        self.send((UInt8(ClientToServerMessages.POINTER_EVENT), pointerEvent))
        
    def sendClientCutText(self, text):
        """
        @summary: write client cut text event packet
        """
        self.send((UInt8(ClientToServerMessages.CUT_TEXT), ClientCutText(text)))
        
class RFBClientListener(object):
    """
    @summary: Interface use to expose event receive from RFB layer
    """
    def recvRectangle(self, rectangle, pixelFormat, data):
        """
        @summary:  Receive rectangle order
                    Main update order type
        @param rectangle: Rectangle type header of packet
        @param pixelFormat: pixelFormat struct of current session
        @param data: image data
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "recvRectangle", "RFBClientListener"))
    
    def onBell(self):
        """
        @summary: receive bip from server
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onBell", "RFBClientListener"))
    
    def onCutText(self, text):
        """
        @summary: Receive cut text from server
        @param text: text inner cut text event
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onCutText", "RFBClientListener"))
    
        
class RFBClientController(RFBClientListener):
    """
    @summary: Class use to manage RFB order and dispatch throw observers for client side
    """
    def __init__(self):
        self._clientObservers = []
        #rfb layer to send client orders
        self._rfbLayer = RFB(self)
        self._isReady = False
        
    def getProtocol(self):
        """
        @return: RFB layer build by controller
        """
        return self._rfbLayer
        
    def addClientObserver(self, observer):
        """
        @summary: Add new observer for this protocol
        @param observer: new observer
        """
        self._clientObservers.append(observer)
        observer._clientListener = self
        
    def getWidth(self):
        """
        @return: width of framebuffer
        """
        return self._rfbLayer._serverInit.width.value
    
    def getHeight(self):
        """
        @return: height of framebuffer
        """
        return self._rfbLayer._serverInit.height.value
    
    def getScreen(self):
        """
        @return: (width, height) of screen
        """
        return (self.getWidth(), self.getHeight())
        
    def setPassword(self, password):
        """
        @summary: set password for vnc authentication type
        @param password: password for session
        """
        self._rfbLayer._password = password
        
    def onReady(self):
        """
        @summary: rfb stack is reday to send or receive event
        """
        self._isReady = True
        for observer in self._clientObservers:
            observer.onReady()
        
    def recvRectangle(self, rectangle, pixelFormat, data):
        """
        @summary:  Receive rectangle order
                    Main update order type
        @param rectangle: Rectangle type header of packet
        @param pixelFormat: pixelFormat struct of current session
        @param data: image data
        """
        for observer in self._clientObservers:
            observer.onUpdate(rectangle.width.value, rectangle.height.value, rectangle.x.value, rectangle.y.value, pixelFormat, rectangle.encoding, data)
    
    def onBell(self):
        """
        @summary: biiiip event
        """
        for observer in self._clientObservers:
            observer.onBell()
    
    def onCutText(self, text):
        """
        @summary: receive cut text event
        @param text: text in cut text event
        """
        for observer in self._clientObservers:
            observer.onCutText(text)
            
    def onClose(self):
        """
        @summary: handle on close events
        """
        if not self._isReady:
            log.debug("Close on non ready layer means authentication error")
            return
        for observer in self._clientObservers:
            observer.onClose()
    
    def sendKeyEvent(self, isDown, key):
        """
        @summary: Send a key event throw RFB protocol
        @param isDown: boolean notify if key is pressed or not (True if key is pressed)
        @param key: ASCII code of key
        """
        if not self._isReady:
            log.info("Try to send key event on non ready layer")
            return
        try:
            event = KeyEvent()
            event.downFlag.value = isDown
            event.key.value = key
        
            self._rfbLayer.sendKeyEvent(event)
        except InvalidValue:
            log.debug("Try to send an invalid key event")
        
    def sendPointerEvent(self, mask, x, y):
        """
        @summary: Send a pointer event throw RFB protocol
        @param mask: mask of button if button 1 and 3 are pressed then mask is 00000101
        @param x: x coordinate of mouse pointer
        @param y: y pointer of mouse pointer
        """
        if not self._isReady:
            log.info("Try to send pointer event on non ready layer")
            return
        try:
            event = PointerEvent()
            event.mask.value = mask
            event.x.value = x
            event.y.value = y
            
            self._rfbLayer.sendPointerEvent(event)
        except InvalidValue:
            log.debug("Try to send an invalid pointer event")
            
    def close(self):
        """
        @summary: close rfb stack
        """
        self._rfbLayer.close()
        

class ClientFactory(RawLayerClientFactory):
    """
    @summary: Twisted Factory of RFB protocol
    """
    def buildRawLayer(self, addr):
        """
        @summary: Function call by twisted on connection
        @param addr: address where client try to connect
        """
        controller = RFBClientController()
        self.buildObserver(controller, addr)
        return controller.getProtocol()
    
    def connectionLost(self, rfblayer, reason):
        """
        @summary: Override this method to handle connection lost
        @param rfblayer: rfblayer that cause connectionLost event
        @param reason: twisted reason
        """
        #call controller
        rfblayer._clientListener.onClose()
    
    def buildObserver(self, controller, addr):
        """
        @summary: Build an RFB observer object
        @param controller: controller use for rfb session
        @param addr: destination
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "buildObserver", "ClientFactory"))
    
        
class RFBClientObserver(object):
    """
    @summary: RFB client protocol observer
    """
    def __init__(self, controller):
        self._controller = controller
        self._controller.addClientObserver(self)
    
    def getController(self):
        """
        @return: RFB controller use by observer
        """
        return self._controller
        
    def keyEvent(self, isPressed, key):
        """
        @summary: Send a key event
        @param isPressed: state of key
        @param key: ASCII code of key
        """
        self._controller.sendKeyEvent(isPressed, key)
        
    def mouseEvent(self, button, x, y):
        """
        @summary: Send a mouse event to RFB Layer
        @param button: button number which is pressed (0,1,2,3,4,5,6,7)
        @param x: x coordinate of mouse pointer
        @param y: y coordinate of mouse pointer
        """
        mask = 0
        if button == 1:
            mask = 1
        elif button > 1:
            mask = 1 << button - 1
            
        self._controller.sendPointerEvent(mask, x, y)
        
    def onReady(self):
        """
        @summary: Event when network stack is ready to receive or send event
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onReady", "RFBClientObserver"))
    
    def onClose(self):
        """
        @summary: On close event
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onClose", "RFBClientObserver"))
    
    def onUpdate(self, width, height, x, y, pixelFormat, encoding, data):
        """
        @summary: Receive FrameBuffer update
        @param width : width of image
        @param height : height of image
        @param x : x position
        @param y : y position
        @param pixelFormat : pixel format struct from rfb.types
        @param encoding : encoding struct from rfb.types
        @param data : in respect of dataFormat and pixelFormat
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onUpdate", "RFBClientObserver"))
    
    def onCutText(self, text):
        """
        @summary: event when server send cut text event
        @param text: text received
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onCutText", "RFBClientObserver"))
    
    def onBell(self):
        """
        @summary: event when server send biiip
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "onBell", "RFBClientObserver"))
