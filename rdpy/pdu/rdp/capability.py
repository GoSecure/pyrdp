from rdpy.enum.rdp import CapabilityType

class Capability:
    def __init__(self, type):
        self.type = type

class GeneralCapability(Capability):
    def __init__(self, majorType, minorType, protocolVersion, generalCompressionTypes, extraFlags, updateCapabilityFlag, remoteUnshareFlag, generalCompressionLevel, refreshRectSupport, suppressOutputSupport):
        Capability.__init__(self, CapabilityType.CAPSTYPE_GENERAL)
        self.majorType = majorType
        self.minorType = minorType
        self.protocolVersion = protocolVersion
        self.generalCompressionTypes = generalCompressionTypes
        self.extraFlags = extraFlags
        self.updateCapabilityFlag = updateCapabilityFlag
        self.remoteUnshareFlag = remoteUnshareFlag
        self.generalCompressionLevel = generalCompressionLevel
        self.refreshRectSupport = refreshRectSupport
        self.suppressOutputSupport = suppressOutputSupport


class BitmapCapability(Capability):
    def __init__(self, preferredBitsPerPixel, receive1BitPerPixel, receive4BitsPerPixel, receive8BitsPerPixel, desktopWidth, desktopHeight, desktopResizeFlag, bitmapCompressionFlag, highColorFlags, drawingFlags, multipleRectangleSupport):
        Capability.__init__(self, CapabilityType.CAPSTYPE_BITMAPCACHE)
        self.preferredBitsPerPixel = preferredBitsPerPixel
        self.receive1BitPerPixel = receive1BitPerPixel
        self.receive4BitsPerPixel = receive4BitsPerPixel
        self.receive8BitsPerPixel = receive8BitsPerPixel
        self.desktopWidth = desktopWidth
        self.desktopHeight = desktopHeight
        self.desktopResizeFlag = desktopResizeFlag
        self.bitmapCompressionFlag = bitmapCompressionFlag
        self.highColorFlags = highColorFlags
        self.drawingFlags = drawingFlags
        self.multipleRectangleSupport = multipleRectangleSupport


class OrderCapability(Capability):
    def __init__(self, terminalDescriptor, desktopSaveXGranularity, desktopSaveYGranularity, maximumOrderLevel, numberFonts, orderFlags, orderSupport, textFlags, orderSupportExFlags, desktopSaveSize, textANSICodePage):
        Capability.__init__(self, CapabilityType.CAPSTYPE_ORDER)
        self.terminalDescriptor = terminalDescriptor
        self.desktopSaveXGranularity = desktopSaveXGranularity
        self.desktopSaveYGranularity = desktopSaveYGranularity
        self.maximumOrderLevel = maximumOrderLevel
        self.numberFonts = numberFonts
        self.orderFlags = orderFlags
        self.orderSupport = orderSupport
        self.textFlags = textFlags
        self.orderSupportExFlags = orderSupportExFlags
        self.desktopSaveSize = desktopSaveSize
        self.textANSICodePage = textANSICodePage


class BitmapCacheV1Capability(Capability):
    def __init__(self, cache0Entries, cache0MaximumCellSize, cache1Entries, cache1MaximumCellSize, cache2Entries, cache2MaximumCellSize):
        Capability.__init__(self, CapabilityType.CAPSTYPE_BITMAPCACHE)
        self.cache0Entries = cache0Entries
        self.cache0MaximumCellSize = cache0MaximumCellSize
        self.cache1Entries = cache1Entries
        self.cache1MaximumCellSize = cache1MaximumCellSize
        self.cache2Entries = cache2Entries
        self.cache2MaximumCellSize = cache2MaximumCellSize


class BitmapCacheV2Capability(Capability):
    def __init__(self, cacheFlags, numCellCaches, bitmapCache0CellInfo, bitmapCache1CellInfo, bitmapCache2CellInfo, bitmapCache3CellInfo, bitmapCache41CellInfo):
        Capability.__init__(self, CapabilityType.CAPSTYPE_BITMAPCACHE_REV2)
        self.cacheFlags = cacheFlags
        self.numCellCaches = numCellCaches
        self.bitmapCache0CellInfo = bitmapCache0CellInfo
        self.bitmapCache1CellInfo = bitmapCache1CellInfo
        self.bitmapCache2CellInfo = bitmapCache2CellInfo
        self.bitmapCache3CellInfo = bitmapCache3CellInfo
        self.bitmapCache41CellInfo = bitmapCache41CellInfo


class ControlCapability(Capability):
    def __init__(self, controlFlags, remoteDetachFlag, controlInterest, detachInterest):
        Capability.__init__(self, CapabilityType.CAPSTYPE_CONTROL)
        self.controlFlags = controlFlags
        self.remoteDetachFlag = remoteDetachFlag
        self.controlInterest = controlInterest
        self.detachInterest = detachInterest


class WindowsActivationCapability(Capability):
    pass

class PointerCapability(Capability):
    pass

class ShareCapability(Capability):
    pass

class ColorCacheCapabilty(Capability):
    pass

class SoundCapability(Capability):
    pass

class InputCapability(Capability):
    pass

class FontCapability(Capability):
    pass

class BrushCapability(Capability):
    pass

class GlyphCacheCapability(Capability):
    pass

class OffscreenBitmapCacheCapability(Capability):
    pass

class VirtualChannelCapability(Capability):
    pass

class DrawNineGridCacheCapability(Capability):
    pass

class DrawGDIPlusCapability(Capability):
    pass

class RemoteProgramsCapability(Capability):
    pass

class WindowListCapability(Capability):
    pass

class DesktopCompositionCapability(Capability):
    pass

class MultifragmentUpdateCapability(Capability):
    pass

class LargePointerCapability(Capability):
    pass

class SurfaceCommandsCapability(Capability):
    pass

class BitmapCodecsCapability(Capability):
    pass

class FrameAcknowledgeCapability(Capability):
    pass