from StringIO import StringIO

from rdpy.core.packing import Uint32LE, Uint16LE

class ClientInfoFlags:
    """
    Flags for the RDPClientInfoPDU flags field
    """
    INFO_MOUSE = 0x00000001
    INFO_DISABLECTRLALTDEL = 0x00000002
    INFO_AUTOLOGON = 0x00000008
    INFO_UNICODE = 0x00000010
    INFO_MAXIMIZESHELL = 0x00000020
    INFO_LOGONNOTIFY = 0x00000040
    INFO_COMPRESSION = 0x00000080
    INFO_ENABLEWINDOWSKEY = 0x00000100
    INFO_REMOTECONSOLEAUDIO = 0x00002000
    INFO_FORCE_ENCRYPTED_CS_PDU = 0x00004000
    INFO_RAIL = 0x00008000
    INFO_LOGONERRORS = 0x00010000
    INFO_MOUSE_HAS_WHEEL = 0x00020000
    INFO_PASSWORD_IS_SC_PIN = 0x00040000
    INFO_NOAUDIOPLAYBACK = 0x00080000
    INFO_USING_SAVED_CREDS = 0x00100000
    INFO_AUDIOCAPTURE = 0x00200000
    INFO_VIDEO_DISABLE = 0x00400000
    INFO_CompressionTypeMask = 0x00001E00

class RDPClientInfoPDU:
    def __init__(self, codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo):
        self.codePage = codePage
        self.flags = flags
        self.domain = domain
        self.username = username
        self.password = password
        self.alternateShell = alternateShell
        self.workingDir = workingDir
        self.extraInfo = extraInfo

class RDPSettingsParser:
    def parse(self, data):
        stream = StringIO(data)
        codePage = Uint32LE.unpack(stream)
        flags = Uint32LE.unpack(stream)

        hasNullBytes = codePage == 1252 or flags & ClientInfoFlags.INFO_UNICODE != 0
        nullByteCount = 1 if hasNullBytes else 0

        domainLength = Uint16LE.unpack(stream) + nullByteCount
        usernameLength = Uint16LE.unpack(stream) + nullByteCount
        passwordLength = Uint16LE.unpack(stream) + nullByteCount
        alternateShellLength = Uint16LE.unpack(stream) + nullByteCount
        workingDirLength = Uint16LE.unpack(stream) + nullByteCount

        domain = stream.read(domainLength)
        username = stream.read(usernameLength)
        password = stream.read(passwordLength)
        alternateShell = stream.read(alternateShellLength)
        workingDir = stream.read(workingDirLength)

        domain = domain.replace("\x00", "")
        username = username.replace("\x00", "")
        password = password.replace("\x00", "")
        alternateShell = alternateShell.replace("\x00", "")
        workingDir = workingDir.replace("\x00", "")

        extraInfo = stream.read()

        return RDPClientInfoPDU(codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo)
    
    def write(self, pdu):
        if not isinstance(pdu, RDPClientInfoPDU):
            raise Exception("Unknown settings PDU type")
        
        stream = StringIO()
        stream.write(Uint32LE.pack(pdu.codePage))
        stream.write(Uint32LE.pack(pdu.flags))
        
        isUnicode = pdu.flags & ClientInfoFlags.INFO_UNICODE != 0
        hasNullBytes = pdu.codePage == 1252 or isUnicode
        nullByteCount = 1 if hasNullBytes else 0
        unicodeMultiplier = 2 if isUnicode else 0

        domain = pdu.domain + "\x00" * nullByteCount
        username = pdu.username + "\x00" * nullByteCount
        password = pdu.password + "\x00" * nullByteCount
        alternateShell = pdu.alternateShell + "\x00" * nullByteCount
        workingDir = pdu.workingDir + "\x00" * nullByteCount

        if isUnicode:
            domain = domain.encode("utf-16le")
            username = username.encode("utf-16le")
            password = password.encode("utf-16le")
            alternateShell = alternateShell.encode("utf-16le")
            workingDir = workingDir.encode("utf-16le")

        domainLength = len(domain) - nullByteCount * unicodeMultiplier
        usernameLength = len(username) - nullByteCount * unicodeMultiplier
        passwordLength = len(password) - nullByteCount * unicodeMultiplier
        alternateShellLength = len(alternateShell) - nullByteCount * unicodeMultiplier
        workingDirLength = len(workingDir) - nullByteCount * unicodeMultiplier
        

        stream.write(Uint16LE.pack(domainLength))
        stream.write(Uint16LE.pack(usernameLength))
        stream.write(Uint16LE.pack(passwordLength))
        stream.write(Uint16LE.pack(alternateShellLength))
        stream.write(Uint16LE.pack(workingDirLength))
        stream.write(domain)
        stream.write(username)
        stream.write(password)
        stream.write(alternateShell)
        stream.write(workingDir)
        stream.write(pdu.extraInfo)

        return stream.getvalue()