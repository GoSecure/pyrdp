from io import BytesIO

from rdpy.core.helper_methods import decodeUTF16LE
from rdpy.core.packing import Uint32LE, Uint16LE
from rdpy.enum.rdp import ClientInfoFlags
from rdpy.pdu.rdp.client_info import RDPClientInfoPDU


class RDPClientInfoParser:
    """
    Read and write the RDP ClientInfo PDU which contains very useful information.
    See https://msdn.microsoft.com/en-us/library/cc240475.aspx
    """

    def parse(self, data):
        """
        Decode a Client Info PDU from bytes.
        :param data: the Client Info PDU bytes.
        :type data: bytes
        :return: RDPClientInfoPDU
        """
        stream = BytesIO(data)
        codePage = Uint32LE.unpack(stream)
        flags = Uint32LE.unpack(stream)

        isUnicode = flags & ClientInfoFlags.INFO_UNICODE != 0
        hasNullBytes = codePage == 1252 or isUnicode
        nullByteCount = 1 if hasNullBytes else 0
        unicodeMultiplier = 2 if isUnicode else 0

        domainLength = Uint16LE.unpack(stream) + nullByteCount * unicodeMultiplier
        usernameLength = Uint16LE.unpack(stream) + nullByteCount * unicodeMultiplier
        passwordLength = Uint16LE.unpack(stream) + nullByteCount * unicodeMultiplier
        alternateShellLength = Uint16LE.unpack(stream) + nullByteCount * unicodeMultiplier
        workingDirLength = Uint16LE.unpack(stream) + nullByteCount * unicodeMultiplier

        domain = stream.read(domainLength)
        username = stream.read(usernameLength)
        password = stream.read(passwordLength)
        alternateShell = stream.read(alternateShellLength)
        workingDir = stream.read(workingDirLength)

        if isUnicode:
            domain = decodeUTF16LE(domain)
            username = decodeUTF16LE(username)
            password = decodeUTF16LE(password)
            alternateShell = decodeUTF16LE(alternateShell)
            workingDir = decodeUTF16LE(workingDir)

        domain = domain
        username = username
        password = password
        alternateShell = alternateShell
        workingDir = workingDir

        extraInfo = stream.read()

        return RDPClientInfoPDU(codePage, flags, domain, username, password, alternateShell, workingDir, extraInfo)

    def write(self, pdu):
        """
        Encode a Client Info PDU to bytes.
        :param pdu: the Client Info PDU.
        :type pdu: RDPClientInfoPDU
        :return: str
        """
        stream = BytesIO()
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