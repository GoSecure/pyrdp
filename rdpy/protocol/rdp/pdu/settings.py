from StringIO import StringIO

from rdpy.core.packing import Uint32LE, Uint16LE

class ClientInfoFlags:
    """
    Flags for the ClientInfoPDU flags field
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

class ClientInfoPDU:
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
        codePage = Uint16LE.unpack(stream)
        flags = Uint16LE.unpack(stream)

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

        return ClientInfoPDU(codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo)
    
    def write(self, pdu):
        if not isinstance(pdu, ClientInfoPDU):
            raise Exception("Unknown settings PDU type")
        
        stream = StringIO()
        stream.write(Uint16LE.pack(pdu.codePage))
        stream.write(Uint16LE.pack(pdu.flags))
        
        hasNullBytes = pdu.codePage == 1252 or pdu.flags & ClientInfoFlags.INFO_UNICODE != 0
        nullByteCount = 1 if hasNullBytes else 0

        domainLength = len(pdu.domain) + nullByteCount
        usernameLength = len(pdu.username) + nullByteCount
        passwordLength = len(pdu.password) + nullByteCount
        alternateShellLength = len(pdu.alternateShell) + nullByteCount
        workingDirLength = len(pdu.workingDir) + nullByteCount
        
        stream.write(pdu.domain + "\x00" * nullByteCount)
        stream.write(pdu.username + "\x00" * nullByteCount)
        stream.write(pdu.password + "\x00" * nullByteCount)
        stream.write(pdu.alternateShell + "\x00" * nullByteCount)
        stream.write(pdu.workingDir + "\x00" * nullByteCount)
        stream.write(pdu.extraInfo)

        return stream.getvalue()