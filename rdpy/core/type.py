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
Raw type use in RDPY

It's a basic implementation looks like google protobuf but dynamically
We are in python!
"""

import struct
from copy import deepcopy
from StringIO import StringIO
from rdpy.core.error import InvalidExpectedDataException, InvalidSize, CallPureVirtualFuntion, InvalidValue
import rdpy.core.log as log

def sizeof(element):
    """
    @summary:  Size in Byte of element.
                Ignore element which conditional is False
    @param element: Type or Tuple(Type | Tuple,)
    @return: size of element in byte or zero for unknown element
    """
    if isinstance(element, tuple) or isinstance(element, list):
        size = 0
        for i in element:
            size += sizeof(i)
        return size
    elif isinstance(element, Type) and element._conditional():
        return element.__sizeof__()
    return 0 

class Type(object):
    """
    @summary:  Root type object inheritance
                Record conditional optional of constant mechanism
    """
    def __init__(self, conditional = lambda:True, optional = False, constant = False):
        """
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        self._conditional = conditional
        self._optional = optional
        self._constant = constant
        #use to record read state
        #if type is optional and not present during read
        #this boolean stay false
        self._is_readed = False
        #use to know if type was written
        self._is_writed = False
        
    def write(self, s):
        """
        @summary:  Check conditional callback 
                    before call __write__ function 
        @param s: Stream that will be written
        """
        self._is_writed = self._conditional()
        if not self._is_writed:
            return
        self.__write__(s)
    
    def read(self, s):
        """
        @summary:  Check conditional callback 
                    Call __read__ function
                    And check constness state after
        @param s: Stream
        @raise InvalidExpectedDataException: if constness is not respected
        """
        self._is_readed = self._conditional()
        if not self._is_readed:
            return
        
        #not constant mode direct reading
        if not self._constant:
            self.__read__(s)
            return
        
        #constant mode
        old = deepcopy(self)
        self.__read__(s)
        #check constant value
        if old != self:
            #rollback read value
            s.pos -= sizeof(self)
            raise InvalidExpectedDataException("%s const value expected %s != %s"%(self.__class__, old.value, self.value))
        
    def __read__(self, s):
        """
        @summary: Interface definition of private read function
        @param s: Stream 
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "__read__", "Type"))
    
    def __write__(self, s):
        """
        @summary: Interface definition of private write function
        @param s: Stream 
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "__write__", "Type"))
    
    def __sizeof__(self):
        """
        @summary: Return size of type use for sizeof function
        @return: size in byte of type
        """
        raise CallPureVirtualFuntion("%s:%s defined by interface %s"%(self.__class__, "__sizeof__", "Type"))
        
class CallableValue(object):
    """
    @summary:  Expression evaluate when is get or set
                Ex: Type contain length of array and array
                To know the size of array you need to read 
                length field before. At ctor time no length was read.
                You need a callable object that will be evaluate when it will be used
    """
    def __init__(self, value):
        """
        @param value: value will be wrapped (raw python type  | lambda | function)
        """
        self._value = None
        self.value = value
    
    def __getValue__(self):
        """
        @summary:  Call when value is get -> Evaluate inner expression
                    Can be overwritten to add specific check before
                    self.value is call
        @return: value expression evaluated
        """
        return self._value()
    
    def __setValue__(self, value):
        """
        @summary:  Call when value is set
                    Can be overwritten to add specific check before
                    self.value = value is call
        @param value: new value wrapped if constant -> lambda function
        """
        value_callable = lambda:value
        if callable(value):
            value_callable = value
            
        self._value = value_callable
    
    @property
    def value(self):
        """
        @summary: Evaluate callable expression
        @return: result of callable value
        """
        return self.__getValue__()
    
    @value.setter
    def value(self, value):
        """
        @summary: Setter of value
        @param value: new value encompass in value type object
        """
        self.__setValue__(value)

class SimpleType(Type, CallableValue):
    """
    @summary:  Non composite type
                leaf in type tree
                And is a callable value
    """
    def __init__(self, structFormat, typeSize, signed, value, conditional = lambda:True, optional = False, constant = False):
        """
        @param structFormat: letter that represent type in struct package
        @param typeSize: size in byte of type
        @param signed: true if type represent a signed type
        @param value: value recorded in this object (raw Python type | lambda | function)
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        self._signed = signed
        self._typeSize = typeSize
        self._structFormat = structFormat
        Type.__init__(self, conditional = conditional, optional = optional, constant = constant)
        CallableValue.__init__(self, value)
        
    def __getValue__(self):
        """
        @summary:  Check value if match range of type
                    And apply sign
                    Ex: UInt8 can be > 255
        @return: Python value wrap into type
        @raise InvalidValue: if value doesn't respect type range
        @see: CallableValue.__getValue__
        """
        value = CallableValue.__getValue__(self)
        
        #check value now because it can be an callable value
        #and evaluate a this time
        
        if not self.isInRange(value):
            raise InvalidValue("value is out of range for %s"%self.__class__)
        if self._signed:
            return value
        else:
            return value & self.mask()

    def __setValue__(self, value):
        """
        @summary:  Check if new value respect type declaration
                    Ex: UInt8 can be > 256
        @param value: new value (raw python type | lambda | function)
        @raise InvalidValue: if value doesn't respect type range
        @see: CallableValue.__setValue__
        """
        #check static value range
        if not callable(value) and not self.isInRange(value):
            raise InvalidValue("value is out of range for %s"%self.__class__)
        
        CallableValue.__setValue__(self, value)
        
    def __write__(self, s):
        """
        @summary:  Write value in stream
                    Use struct package to pack value
                    In accordance of structFormat field
        @param s: Stream that will be written
        """
        s.write(struct.pack(self._structFormat, self.value))
        
    def __read__(self, s):
        """
        @summary:  Read inner value from stream
                    Use struct package to unpack
                    In accordance of structFormat and typeSize fields
        @param s: Stream that will be read
        @raise InvalidSize: if there is not enough data in stream
        """
        data = ""
        while len(data) < self._typeSize:
            if s.eof():
                raise InvalidSize("Stream is too small to read expected SimpleType")
            
            read_size = self._typeSize - len(data)
            data += s.read(read_size)

        self.value = struct.unpack(self._structFormat, data)[0]
      
    def mask(self):
        """
        @summary:  Compute bit mask for type
                    Because in Python all numbers are Int long or float
                    Cache result in self._mask field
        """
        if not self.__dict__.has_key("_mask"):
            mask = 0xff
            for _ in range(1, self._typeSize):
                mask = mask << 8 | 0xff
            self._mask = mask
        return self._mask
    
    def isInRange(self, value):
        """
        @summary: Check if value is in range represented by mask
        @param value: Python value
        @return: true if value is in type range
        """
        if self._signed:
            return not (value < -(self.mask() >> 1) or value > (self.mask() >> 1))
        else:
            return not (value < 0 or value > self.mask())
        
    def __sizeof__(self):
        """
        @summary: Return size of type in bytes
        @return: typeSize pass in constructor
        """
        return self._typeSize
    
    def __cmp__(self, other):
        """
        @summary:  Compare two simple type
                    Call inner value compare operator
        @param other:  SimpleType value or try to build same type as self
                        around value
        @return: python value compare
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.value.__cmp__(other.value)
    
    def __invert__(self):
        """
        @summary: Implement not operator
        @return: not inner value
        """
        invert = ~self.value
        if not self._signed:
            invert &= self.mask()
        return self.__class__(invert)
    
    def __add__(self, other):
        """
        @summary: Implement addition operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: add operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__add__(other.value))
    
    def __sub__(self, other):
        """
        @summary: Implement sub operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: sub operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__sub__(other.value))
    
    def __and__(self, other):
        """
        @summary: Implement bitwise and operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: and operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__and__(other.value))
    
    def __or__(self, other):
        """
        @summary: Implement bitwise or operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: or operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__or__(other.value))
    
    def __xor__(self, other):
        """
        @summary: Implement bitwise xor operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: xor operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__xor__(other.value))
    
    def __lshift__(self, other):
        """
        @summary: Left shift operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: lshift operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__lshift__(other.value))
    
    def __rshift__(self, other):
        """
        @summary: Right shift operator
        @param other:  SimpleType value or try to construct same type as self
                        around other value
        @return: rshift operator of inner values
        @raise InvalidValue: if new value is out of bound
        """
        if not isinstance(other, SimpleType):
            other = self.__class__(other)
        return self.__class__(self.value.__rshift__(other.value))
    
    def __hash__(self):
        """
        @summary: Hash function to handle simple type in hash collection
        @return: hash of inner value
        """
        return hash(self.value)
    
    def __nonzero__(self):
        """
        @summary: Boolean conversion
        @return: bool of inner value
        """
        return bool(self.value)

        
class CompositeType(Type):
    """
    @summary:  Type node in Type tree
                Track type field declared in __init__ function
                Ex: self.lengthOfPacket = UInt16Le() -> record lengthOfPacket as sub type of node
    """
    def __init__(self, conditional = lambda:True, optional = False, constant = False, readLen = None):
        """
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        @param readLen:    Max length in bytes can be readed from stream
                            Use to check length information
        """
        Type.__init__(self, conditional = conditional, optional = optional, constant = constant)
        #list of ordoned type
        self._typeName = []
        self._readLen = readLen
    
    def __setattr__(self, name, value):
        """
        @summary:  Track Type field
                    For Type field record it in same order as declared
                    Keep other but bot handle in read or write function
        @param name: name of new attribute
        @param value: value of new attribute
        """
        if name[0] != '_' and (isinstance(value, Type) or isinstance(value, tuple)) and not name in self._typeName:
            self._typeName.append(name)
        self.__dict__[name] = value
            
    def __read__(self, s):
        """
        @summary:  Read composite type
                    Call read on each ordered sub-type
                    And check read length parameter
                    If an error occurred rollback type already read
        @param s: Stream
        @raise InvalidSize: if stream is greater than readLen parameter
        """
        readLen = 0
        for name in self._typeName:            
            try:
                s.readType(self.__dict__[name])
                readLen += sizeof(self.__dict__[name])
                #read is ok but read out of bound
                if not self._readLen is None and readLen > self._readLen.value:
                    #roll back
                    s.pos -= sizeof(self.__dict__[name])
                    #and notify if not optional
                    if not self.__dict__[name]._optional:
                        raise InvalidSize("Impossible to read type %s : read length is too small"%(self.__class__))
                
            except Exception as e:
                log.error("Error during read %s::%s"%(self.__class__, name))
                #roll back already read
                for tmpName in self._typeName:
                    if tmpName == name:
                        break
                    s.pos -= sizeof(self.__dict__[tmpName])
                raise e
            
        if not self._readLen is None and readLen < self._readLen.value:
            log.debug("Still have correct data in packet %s, read %s bytes as padding"%(self.__class__, self._readLen.value - readLen))
            s.read(self._readLen.value - readLen)
            
    def __write__(self, s):
        """
        @summary:  Write all sub-type handle by __setattr__ function
                    Call write on each ordered sub type
        @param s: Stream
        """
        for name in self._typeName:
            try:
                s.writeType(self.__dict__[name])
            except Exception as e:
                log.error("Error during write %s::%s"%(self.__class__, name))
                raise e
            
    def __sizeof__(self):
        """
        @summary: Call sizeof on each sub type
        @return: sum of sizeof of each Type attributes
        """
        if self._is_readed and not self._readLen is None:
            return self._readLen.value
        
        size = 0
        for name in self._typeName:
            size += sizeof(self.__dict__[name])
        return size

    def __eq__(self, other):
        """
        @summary:  Compare each properties which are Type inheritance
                    if one is different then not equal
        @param other: CompositeType
        @return: True if each sub-type are equals
        """
        if self._typeName != other._typeName:
            return False
        for name in self._typeName:
            if self.__dict__[name] != other.__dict__[name]:
                return False
        return True
    
    def __ne__(self, other):
        """
        @summary: return not equal result operator
        @param other: CompositeType
        @return: False if each subtype are equals
        """
        return not self.__eq__(other)

"""
All simple Raw type use in RDPY
"""

class UInt8(SimpleType):
    """
    @summary: unsigned byte
    """    
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "B", 1, False, value, conditional = conditional, optional = optional, constant = constant)

class SInt8(SimpleType):
    """
    @summary: signed byte
    """   
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "b", 1, True, value, conditional = conditional, optional = optional, constant = constant)
        
        
class UInt16Be(SimpleType):
    """
    @summary: unsigned short
               with Big endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, ">H", 2, False, value, conditional = conditional, optional = optional, constant = constant)
        
class UInt16Le(SimpleType):
    """
    @summary: unsigned short
               with Little endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "<H", 2, False, value, conditional = conditional, optional = optional, constant = constant)
        
class SInt16Le(SimpleType):
    """
    @summary: signed short
               with Little endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "<h", 2, True, value, conditional = conditional, optional = optional, constant = constant)
        
class UInt32Be(SimpleType):
    """
    @summary: unsigned int
               with Big endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, ">I", 4, False, value, conditional = conditional, optional = optional, constant = constant)
        
class UInt32Le(SimpleType):
    """
    @summary: unsigned int
               with Little endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "<I", 4, False, value, conditional = conditional, optional = optional, constant = constant)
    
class SInt32Le(SimpleType):
    """
    @summary: signed int
               with Little endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "<I", 4, True, value, conditional = conditional, optional = optional, constant = constant)
        
class SInt32Be(SimpleType):
    """
    @summary: signed int
               with Big endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, ">I", 4, True, value, conditional = conditional, optional = optional, constant = constant)
        
class UInt24Be(SimpleType):
    """
    @summary: unsigned 24 bit integer
               with Big endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, ">I", 3, False, value, conditional = conditional, optional = optional, constant = constant)
        
    def __write__(self, s):
        """
        @summary: special write for a special type
        @param s: Stream
        """
        s.write(struct.pack(">I", self.value)[1:])
        
    def __read__(self, s):
        """
        @summary: special read for a special type
        @param s: Stream
        """
        self.value = struct.unpack(self._structFormat, '\x00' + s.read(self._typeSize))[0]
        
class UInt24Le(SimpleType):
    """
    @summary: unsigned 24 bit integer
               with Little endian representation in stream
    """
    def __init__(self, value = 0, conditional = lambda:True, optional = False, constant = False):
        """
        @param value: python value wrap
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        SimpleType.__init__(self, "<I", 3, False, value, conditional = conditional, optional = optional, constant = constant)   
            
    def __write__(self, s):
        """
        @summary: special write for a special type
        @param s: Stream
        """
        #don't write first byte
        s.write(struct.pack("<I", self.value)[:3])
        
    def __read__(self, s):
        """
        @summary: special read for a special type
        @param s: Stream
        """
        self.value = struct.unpack(self._structFormat, s.read(self._typeSize) + '\x00')[0]
        
class String(Type, CallableValue):
    """
    @summary:  String type
                Leaf in Type tree
    """
    def __init__(self, value = "", readLen = None, conditional = lambda:True, optional = False, constant = False, unicode = False, until = None):
        """
        @param value: python string use for inner value
        @param readLen: length use to read in stream (SimpleType) if 0 read entire stream
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        @param unicode: Encode and decode value as unicode
        @param until: read until sequence is readed or write sequence at the end of string
        """
        Type.__init__(self, conditional = conditional, optional = optional, constant = constant)
        CallableValue.__init__(self, value)
        #type use to know read length
        self._readLen = readLen
        self._unicode = unicode
        self._until = until
        
    def __cmp__(self, other):
        """
        @summary: call raw compare value
        @param other: other String parameter
        @return: if two inner value are equals
        """
        return cmp(self.value, other.value)
    
    def __hash__(self):
        """
        @summary: hash function to treat simple type in hash collection
        @return: hash of inner value
        """
        return hash(self.value)
    
    def __str__(self):
        """
        @summary: call when str function is call
        @return: inner python string
        """
        return self.value
    
    def __write__(self, s):
        """
        @summary:  Write the inner value after evaluation
                    Append until sequence if present
                    Encode in unicode format if asked
        @param s: Stream
        """
        toWrite = self.value
        
        if not self._until is None:
            toWrite += self._until
            
        if self._unicode:
            s.write(encodeUnicode(self.value))
        else:
            s.write(self.value)
    
    def __read__(self, s):
        """
        @summary:  Read readLen bytes as string
                    If readLen is None read until 'until' sequence match
                    If until sequence is None read until end of stream
        @param s: Stream
        """
        if self._readLen is None:
            if self._until is None:
                self.value = s.getvalue()[s.pos:]
            else:
                self.value = ""
                while self.value[-len(self._until):] != self._until and not s.eof():
                    self.value += s.read(1)
        else:
            self.value = s.read(self._readLen.value)
        
        if self._unicode:
            self.value = decodeUnicode(self.value)
        
    def __sizeof__(self):
        """
        @summary:  return length of string
                    if string is unicode encode return 2*len(str) + 2
        @return: length of inner string
        """
        if self._unicode:
            return 2 * len(self.value) + 2
        else:
            return len(self.value)
    
def encodeUnicode(s):
    """
    @summary: Encode string in unicode
    @param s: str python
    @return: unicode string
    """
    return "".join([c + "\x00" for c in s]) + "\x00\x00"

def decodeUnicode(s):
    """
    @summary: Decode Unicode string
    @param s: unicode string
    @return: str python
    """
    i = 0
    r = ""
    while i < len(s) - 2:
        if i % 2 == 0:
            r += s[i]
        i += 1
    return r

class StringStream(StringIO):
    """
    @summary:  Stream use to read all types
    """
    def eof(self):
        """
        @return: whether the stream has reached its end
        """
        return self.pos == self.len
    
    def readLen(self):
        """
        @summary: compute already read size
        @return: read size of stream
        """
        return self.pos
    
    def readType(self, value):
        """
        @summary:  call specific read on type object
                    or iterate over tuple elements
                    rollback read if error occurred during read value
        @param value: (tuple | Type) object
        """
        #read each tuple
        if isinstance(value, tuple) or isinstance(value, list):
            for element in value:
                try:
                    self.readType(element)
                except Exception as e:
                    #rollback already readed elements
                    for tmpElement in value:
                        if tmpElement == element:
                            break
                        self.pos -= sizeof(tmpElement)
                    raise e
            return
        
        #optional value not present
        if self.eof() and value._optional:
            return

        value.read(self)
        
    def readNextType(self, t):
        """
        @summary: read next type but didn't consume it
        @param t: Type element
        """
        self.readType(t)
        self.pos -= sizeof(t)
    
    def writeType(self, value):
        """
        @summary:  Call specific write on type object
                    or iterate over tuple element
        @param value: (tuple | Type)
        """
        #write each element of tuple
        if isinstance(value, tuple) or isinstance(value, list):
            for element in value:
                self.writeType(element)
            return
        value.write(self)

class SocketStream:
    def __init__(self, sock, buffer_size = 4096):
        self.sock = sock
        self.is_eof = False
        self.buffer = ""
        self.buffer_size = buffer_size
    
    def eof(self):
        return self.is_eof
    
    def read(self, count):
        while count > len(self.buffer) and not self.eof():
            data = self.sock.recv(self.buffer_size)

            if data == "":
                self.is_eof = True
            
            self.buffer += data

        data = self.buffer[: count]
        self.buffer = self.buffer[count :]
        return data
    
    def write(self, data):
        self.sock.send(data)
    
    def readType(self, value):
        """
        @summary:  call specific read on type object
                    or iterate over tuple elements
                    rollback read if error occurred during read value
        @param value: (tuple | Type) object
        """
        #read each tuple
        if isinstance(value, tuple) or isinstance(value, list):
            for element in value:
                self.readType(element)
            return
        
        #optional value not present
        if self.eof() and value._optional:
            return

        value.read(self)
    
    def writeType(self, value):
        """
        @summary:  Call specific write on type object
                    or iterate over tuple element
        @param value: (tuple | Type)
        """
        #write each element of tuple
        if isinstance(value, tuple) or isinstance(value, list):
            for element in value:
                self.writeType(element)
            return
        
        value.write(self)


class ArrayType(Type):
    """
    @summary: Factory af n element
    """
    def __init__(self, typeFactory, init = None, readLen = None, conditional = lambda:True, optional = False, constant = False):
        """
        @param typeFactory: class use to init new element on read
        @param init: init array
        @param readLen: number of element in sequence
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        Type.__init__(self, conditional, optional, constant)
        self._typeFactory = typeFactory
        self._readLen = readLen
        self._array = []
        if not init is None:
            self._array = init
        
    def __read__(self, s):
        """
        @summary: Create readLen new object and read it
        @param s: Stream
        """
        self._array = []
        i = 0
        #self._readLen is None means that array will be read until end of stream
        while self._readLen is None or i < self._readLen.value:
            element = self._typeFactory()
            element._optional = self._readLen is None
            s.readType(element)
            if not element._is_readed:
                break
            self._array.append(element)
            i += 1
    
    def __write__(self, s):
        """
        @summary: Just write array
        @param s: Stream
        """
        s.writeType(self._array)
        
    def __getitem__(self, item):
        """
        @summary: Magic function to be FactoryType as transparent as possible
        @return: index of _value
        """
        return self._array.__getitem__(item)
    
    def __sizeof__(self):
        """
        @summary: Size in bytes of all inner type
        """
        return sizeof(self._array)
    
class FactoryType(Type):
    """
    @summary:  Call a factory callback at read or write time
                Wrapp attribute access to inner type
    """
    def __init__(self, factory, conditional = lambda:True, optional = False, constant = False):
        """
        @param factory: Call back call before read or write type
        @param conditional :    Callable object
                                 Read and Write operation depend on return of this function
        @param optional:   If there is no enough byte in current stream
                            And optional is True, read type is ignored
        @param constant:   Check if object value doesn't change after read operation
        """
        Type.__init__(self, conditional, optional, constant)
        self._factory = factory
        if not callable(factory):
            self._factory = lambda:factory

        self._value = None
    
    def __read__(self, s):
        """
        @summary: Call factory and write it
        @param s: Stream
        """
        self._value = self._factory()
        s.readType(self._value)
        
    def __write__(self, s):
        """
        @summary: Call factory and read it
        @param s: Stream
        """
        self._value = self._factory()
        s.writeType(self._value)
    
    def __getattr__(self, name):
        """
        @summary: Magic function to be FactoryType as transparent as possible
        @return: _value parameter
        """
        return self._value.__getattribute__(name)
    
    def __getitem__(self, item):
        """
        @summary: Magic function to be FactoryType as transparent as possible
        @return: index of _value
        """
        return self._value.__getitem__(item)
    
    def __sizeof__(self):
        """
        @summary: Size of of object returned by factory
        @return: Size of of object returned by factory
        """
        return sizeof(self._value)

    def __iter__(self):
        self.current = 0
        return self

    def next(self):
        if self.current >= len(self._typeName):
            raise StopIteration
        else:
            self.current += 1
            return self._typeName[self.current-1]

def CheckValueOnRead(cls):
    """
    @summary:  Wrap read method of class
                to check value on read
                if new value is different from old value
    @param cls: class that inherit from Type
    @raise InvalidValue: if constness is not respected
    """
    oldRead = cls.read
    def read(self, s):
        old = deepcopy(self)
        oldRead(self, s)
        if self != old:
            raise InvalidValue("CheckValueOnRead %s != %s"%(self, old))
    cls.read = read
    return cls