from rdpy.enum.rdp import CapabilityType


class Capability:
    def __init__(self, type, rawData=""):
        """
        :type type: int
        :type rawData: str
        """
        self.type = type
        self.rawData = rawData


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
        Capability.__init__(self, CapabilityType.CAPSTYPE_BITMAP)
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
    def __init__(self, helpKeyFlag, helpKeyIndexFlag, helpExtendedKeyFlag, windowManagerKeyFlag):
        Capability.__init__(self, CapabilityType.CAPSTYPE_ACTIVATION)
        self.helpKeyFlag = helpKeyFlag
        self.helpKeyIndexFlag = helpKeyIndexFlag
        self.helpExtendedKeyFlag = helpExtendedKeyFlag
        self.windowManagerKeyFlag = windowManagerKeyFlag


class PointerCapability(Capability):
    def __init__(self, colorPointerFlag, colorPointerCacheSize, pointerCacheSize):
        Capability.__init__(self, CapabilityType.CAPSTYPE_POINTER)
        self.colorPointerFlag = colorPointerFlag
        self.colorPointerCacheSize = colorPointerCacheSize
        self.pointerCacheSize = pointerCacheSize


class ShareCapability(Capability):
    def __init__(self, nodeID):
        Capability.__init__(self, CapabilityType.CAPSTYPE_SHARE)
        self.nodeID = nodeID


class ColorCacheCapabilty(Capability):
    def __init__(self, colorTableCacheSize):
        Capability.__init__(self, CapabilityType.CAPSTYPE_COLORCACHE)
        self.colorTableCacheSize = colorTableCacheSize


class SoundCapability(Capability):
    def __init__(self, soundFlags):
        Capability.__init__(self, CapabilityType.CAPSTYPE_SOUND)
        self.soundFlags = soundFlags


class InputCapability(Capability):
    def __init__(self, inputFlags, keyboardLayout, keyboardType, keyboardSubType, keyboardFunctionKey, imeFileName):
        Capability.__init__(self, CapabilityType.CAPSTYPE_INPUT)
        self.inputFlags = inputFlags
        self.keyboardLayout = keyboardLayout
        self.keyboardType = keyboardType
        self.keyboardSubType = keyboardSubType
        self.keyboardFunctionKey = keyboardFunctionKey
        self.imeFileName = imeFileName


class FontCapability(Capability):
    def __init__(self, fontSupportFlags):
        Capability.__init__(self, CapabilityType.CAPSTYPE_FONT)
        self.fontSupportFlags = fontSupportFlags


class BrushCapability(Capability):
    def __init__(self, brushSupportLevel):
        Capability.__init__(self, CapabilityType.CAPSTYPE_BRUSH)
        self.brushSupportLevel = brushSupportLevel


class GlyphCacheCapability(Capability):
    def __init__(self, glyphCache, fragCache, glyphSupportLevel):
        Capability.__init__(self, CapabilityType.CAPSTYPE_GLYPHCACHE)
        self.glyphCache = glyphCache
        self.fragCache = fragCache
        self.glyphSupportLevel = glyphSupportLevel


class OffscreenBitmapCacheCapability(Capability):
    def __init__(self, offscreenSupportLevel, offscreenCacheSize, offscreenCacheEntries):
        Capability.__init__(self, CapabilityType.CAPSTYPE_OFFSCREENCACHE)
        self.offscreenSupportLevel = offscreenSupportLevel
        self.offscreenCacheSize = offscreenCacheSize
        self.offscreenCacheEntries = offscreenCacheEntries


class BitmapCacheHostSupportCapability(Capability):
    def __init__(self, cacheVersion):
        Capability.__init__(self, CapabilityType.CAPSTYPE_BITMAPCACHE_HOSTSUPPORT)
        self.cacheVersion = cacheVersion


class VirtualChannelCapability(Capability):
    def __init__(self, flags, vcChunkSize):
        Capability.__init__(self, CapabilityType.CAPSTYPE_VIRTUALCHANNEL)
        self.flags = flags
        self.vcChunkSize = vcChunkSize


class DrawNineGridCacheCapability(Capability):
    def __init__(self, drawNineGridSupportLevel, drawNineGridCacheSize, drawNineGridCacheEntries):
        Capability.__init__(self, CapabilityType.CAPSTYPE_DRAWNINEGRIDCACHE)
        self.drawNineGridSupportLevel = drawNineGridSupportLevel
        self.drawNineGridCacheSize = drawNineGridCacheSize
        self.drawNineGridCacheEntries = drawNineGridCacheEntries


class DrawGDIPlusCapability(Capability):
    def __init__(self, drawGDIPlusSupportLevel, gdipVersion, drawGDIPlusCacheLevel, gdipCacheEntries, gdipCacheChunkSize, gdipImageCacheProperties):
        Capability.__init__(self, CapabilityType.CAPSTYPE_DRAWGDIPLUS)
        self.drawGDIPlusSupportLevel = drawGDIPlusSupportLevel
        self.gdipVersion = gdipVersion
        self.drawGDIPlusCacheLevel = drawGDIPlusCacheLevel
        self.gdipCacheEntries = gdipCacheEntries
        self.gdipCacheChunkSize = gdipCacheChunkSize
        self.gdipImageCacheProperties = gdipImageCacheProperties


class RemoteProgramsCapability(Capability):
    def __init__(self, railSupportLevel):
        Capability.__init__(self, CapabilityType.CAPSTYPE_RAIL)
        self.railSupportLevel = railSupportLevel


class WindowListCapability(Capability):
    def __init__(self, wndSupportLevel, numIconCaches, numIconCacheEntries):
        Capability.__init__(self, CapabilityType.CAPSTYPE_WINDOW)
        self.wndSupportLevel = wndSupportLevel
        self.numIconCaches = numIconCaches
        self.numIconCacheEntries = numIconCacheEntries


class DesktopCompositionCapability(Capability):
    def __init__(self, compDeskSupportLevel):
        Capability.__init__(self, CapabilityType.CAPSETTYPE_COMPDESK)
        self.compDeskSupportLevel = compDeskSupportLevel


class MultifragmentUpdateCapability(Capability):
    def __init__(self, maxRequestSize):
        Capability.__init__(self, CapabilityType.CAPSETTYPE_MULTIFRAGMENTUPDATE)
        self.maxRequestSize = maxRequestSize


class LargePointerCapability(Capability):
    def __init__(self, largePointerSupportFlags):
        Capability.__init__(self, CapabilityType.CAPSETTYPE_LARGE_POINTER)
        self.largePointerSupportFlags = largePointerSupportFlags


class SurfaceCommandsCapability(Capability):
    def __init__(self, cmdFlags, reserved):
        Capability.__init__(self, CapabilityType.CAPSETTYPE_SURFACE_COMMANDS)
        self.cmdFlags = cmdFlags
        self.reserved = reserved


class BitmapCodecsCapability(Capability):
    def __init__(self, supportedBitmapCodecs):
        Capability.__init__(self, CapabilityType.CAPSETTYPE_BITMAP_CODECS)
        self.supportedBitmapCodecs = supportedBitmapCodecs


class BitmapCodec:
    def __init__(self, guid, id, properties):
        self.guid = guid
        self.id = id
        self.properties = properties


class NSCodec:
    def __init__(self, allowDynamicFidelity, allowSubsampling, colorLossLevel):
        self.allowDynamicFidelity = allowDynamicFidelity
        self.allowSubsampling = allowSubsampling
        self.colorLossLevel = colorLossLevel


class ClientCapsContainer:
    def __init__(self, captureFlags, rfxCapset):
        self.captureFlags = captureFlags
        self.rfxCaps = rfxCapset


class RFXCapset:
    def __init__(self, id, capsetType, icaps):
        self.id = id
        self.capsetType = capsetType
        self.icaps = icaps


class RFXIcap:
    def __init__(self, flags, entropyBits):
        self.flags = flags
        self.entropyBits = entropyBits
        

class ServerCapsContainer:
    def __init__(self, reserved):
        self.reserved = reserved


class FrameAcknowledgeCapability(Capability):
    def __init__(self, maxUnacknowledgedFrameCount):
        Capability.__init__(self, CapabilityType.CAPSSETTYPE_FRAME_ACKNOWLEDGE)
        self.maxUnacknowledgedFrameCount = maxUnacknowledgedFrameCount
