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
import hashlib

from pyrdp.core.packing import Uint32LE
from pyrdp.core.stream import ByteStream
from pyrdp.security import rc4
from pyrdp.enum.rdp import EncryptionMethod


def saltedHash(inputData, salt, salt1, salt2):
    """
    Generate a signature from a combination of sha1 and md5.
    Signature = MD5(Salt + SHA1(Input + Salt + Salt1 + Salt2))
    See: http://msdn.microsoft.com/en-us/library/cc241992.aspx
    :param inputData: strange input (see doc)
    :type inputData: bytes
    :param salt: salt for context call
    :type salt: bytes
    :param salt1: another salt (ex : client random)
    :type salt1: bytes
    :param salt2: another salt (ex: server random)
    :type salt2: bytes
    :return: str
    """
    sha1Digest = hashlib.sha1()
    md5Digest = hashlib.md5()

    sha1Digest.update(inputData)
    sha1Digest.update(salt[:48])
    sha1Digest.update(salt1)
    sha1Digest.update(salt2)
    sha1Sig = sha1Digest.digest()

    md5Digest.update(salt[:48])
    md5Digest.update(sha1Sig)

    return md5Digest.digest()


def finalHash(key, random1, random2):
    """
    Hash = MD5(in0[:16] + in1[:32] + in2[:32])
    :param key: 16 byte string
    :type key: bytes
    :param random1: 32 byte random string
    :type random1: bytes
    :param random2: 32 byte random string
    :type random2: bytes
    :return: MD5(in0[:16] + in1[:32] + in2[:32])
    """
    md5Digest = hashlib.md5()
    md5Digest.update(key)
    md5Digest.update(random1)
    md5Digest.update(random2)
    return md5Digest.digest()


def generateMasterSecret(preMasterSecret, clientRandom, serverRandom):
    """
    Generate master secret.
    See: http://msdn.microsoft.com/en-us/library/cc241992.aspx
    :param preMasterSecret: secret
    :type preMasterSecret: bytes
    :param clientRandom: client random
    :type clientRandom: bytes
    :param serverRandom: server random
    :type serverRandom: bytes
    """
    return saltedHash(b"A", preMasterSecret, clientRandom, serverRandom) + saltedHash(b"BB", preMasterSecret, clientRandom, serverRandom) + saltedHash(b"CCC", preMasterSecret, clientRandom, serverRandom)


def generateSessionKeyBlob(masterSecret, clientRandom, serverRandom):
    """
    Generate session key blob.
    :param masterSecret: secret
    :type masterSecret: bytes
    :param clientRandom: client random
    :type clientRandom: bytes
    :param serverRandom: server random
    :type serverRandom: bytes
    """
    return saltedHash(b"X", masterSecret, clientRandom, serverRandom) + saltedHash(b"YY", masterSecret, clientRandom, serverRandom) + saltedHash(b"ZZZ", masterSecret, clientRandom, serverRandom)


def macData(macKey, data):
    """
    Generate an unsalted signature.
    See: http://msdn.microsoft.com/en-us/library/cc241995.aspx
    :param macKey: signing key.
    :type macKey: bytes
    :param data: data to sign.
    :type data: bytes
    :return: str
    """
    sha1Digest = hashlib.sha1()
    md5Digest = hashlib.md5()

    dataLength = ByteStream()
    Uint32LE.pack(len(data), dataLength)

    sha1Digest.update(macKey)
    sha1Digest.update(b"\x36" * 40)
    sha1Digest.update(dataLength.getvalue())
    sha1Digest.update(data)

    sha1Sig = sha1Digest.digest()

    md5Digest.update(macKey)
    md5Digest.update(b"\x5c" * 48)
    md5Digest.update(sha1Sig)

    return md5Digest.digest()


def macSaltedData(macKey, data, encryptionCount):
    """
    Generate a salted signature.
    See: https://msdn.microsoft.com/en-us/library/cc240789.aspx
    :param macKey: signing key.
    :type macKey: bytes
    :param data: data to sign.
    :type data: bytes
    :param encryptionCount: the number of encrypted packets so far.
    :type encryptionCount: int
    :return: str
    """
    sha1Digest = hashlib.sha1()
    md5Digest = hashlib.md5()

    dataLengthS = ByteStream()
    Uint32LE.pack(len(data), dataLengthS)

    encryptionCountS = ByteStream()
    Uint32LE.pack(encryptionCount, encryptionCountS)

    sha1Digest.update(macKey)
    sha1Digest.update(b"\x36" * 40)
    sha1Digest.update(dataLengthS.getvalue())
    sha1Digest.update(data)
    sha1Digest.update(encryptionCountS.getvalue())

    sha1Sig = sha1Digest.digest()

    md5Digest.update(macKey)
    md5Digest.update(b"\x5c" * 48)
    md5Digest.update(sha1Sig)

    return md5Digest.digest()


def tempKey(initialKey, currentKey):
    """
    Create a temporary updated key.
    See: http://msdn.microsoft.com/en-us/library/cc240792.aspx
    :param initialKey: starting key.
    :param currentKey: current key.
    :return: str
    """
    sha1Digest = hashlib.sha1()
    md5Digest = hashlib.md5()

    sha1Digest.update(initialKey)
    sha1Digest.update(b"\x36" * 40)
    sha1Digest.update(currentKey)

    sha1Sig = sha1Digest.digest()

    md5Digest.update(initialKey)
    md5Digest.update(b"\x5c" * 48)
    md5Digest.update(sha1Sig)

    return md5Digest.digest()


def gen40bits(data):
    """
    Generate 40 bits of data from 128 bits of data for key computation.
    See: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    :param data: 128 bits string
    :type data: bytes
    :return: dict
    """
    return b"\xd1\x26\x9e" + data[:8][-5:]


def gen56bits(data):
    """
    Generate 56 bits of data from 128 bits of data for key computation.
    See: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    :param data: 128 bits string
    :type data: bytes
    :return: str
    """
    return b"\xd1" + data[:8][-7:]


def generateKeys(clientRandom, serverRandom, method):
    """
    Generate cryptographic keys based on client and server random values and a method.
    Returns the mac key, the server-client encryption key and the client-server encryption key.
    See: http://msdn.microsoft.com/en-us/library/cc240785.aspx
    :param method: the EncryptionMethod value.
    :type method: EncryptionMethod
    :param clientRandom: the client random.
    :type clientRandom: bytes
    :param serverRandom: the server random.
    :type serverRandom: bytes
    :return: str, str, str
    """
    preMasterHash = clientRandom[:24] + serverRandom[:24]
    masterHash = generateMasterSecret(preMasterHash, clientRandom, serverRandom)
    sessionKey = generateSessionKeyBlob(masterHash, clientRandom, serverRandom)
    macKey128 = sessionKey[:16]
    initialFirstKey128 = finalHash(sessionKey[16: 32], clientRandom, serverRandom)
    initialSecondKey128 = finalHash(sessionKey[32: 48], clientRandom, serverRandom)

    if method == EncryptionMethod.ENCRYPTION_40BIT:
        return gen40bits(macKey128), gen40bits(initialFirstKey128), gen40bits(initialSecondKey128)
    elif method == EncryptionMethod.ENCRYPTION_56BIT:
        return gen56bits(macKey128), gen56bits(initialFirstKey128), gen56bits(initialSecondKey128)
    elif method == EncryptionMethod.ENCRYPTION_128BIT:
        return macKey128, initialFirstKey128, initialSecondKey128

    raise ValueError("Bad encryption method")


def updateKey(initialKey, currentKey, method):
    """
    Update a key.
    See: http://msdn.microsoft.com/en-us/library/cc240792.aspx
    :param initialKey: initial key.
    :type initialKey: bytes
    :param currentKey: current key.
    :type currentKey: bytes
    :param method: encryption method.
    :type method: EncryptionMethod
    :return: str
    """
    if method == EncryptionMethod.ENCRYPTION_40BIT:
        tempKey128 = tempKey(initialKey[:8], currentKey[:8])
        return gen40bits(rc4.crypt(rc4.RC4Key(tempKey128[:8]), tempKey128[:8]))
    elif method == EncryptionMethod.ENCRYPTION_56BIT:
        tempKey128 = tempKey(initialKey[:8], currentKey[:8])
        return gen56bits(rc4.crypt(rc4.RC4Key(tempKey128[:8]), tempKey128[:8]))
    elif method == EncryptionMethod.ENCRYPTION_128BIT:
        tempKey128 = tempKey(initialKey, currentKey)
        return rc4.crypt(rc4.RC4Key(tempKey128), tempKey128)