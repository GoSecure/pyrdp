#
# This file is part of the PyRDP project.
# Copyright (C) 2018, 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
File that contains helper methods to use in the library.
"""
import argparse
import logging
import os
import sys
from logging import Logger
from typing import Tuple

import appdirs
import OpenSSL

from pyrdp.core.ssl import ServerTLSContext


def decodeUTF16LE(data: bytes) -> str:
    """
    Decode the provided bytes in UTF-16 in a way that does not crash when invalid input is provided.
    :param data: The data to decode as utf-16.
    :return: The python string
    """
    return data.decode("utf-16le", errors="ignore")


def encodeUTF16LE(string: str) -> bytes:
    """
    Encode the provided string in UTF-16 in a way that does not crash when invalid input is provided.
    :param string: The python string to encode to bytes
    :return: The raw bytes
    """
    return string.encode("utf-16le", errors="ignore")


def getLoggerPassFilters(loggerName: str) -> Logger:
    """
    Returns a logger instance where the filters of all the parent chain are applied to it.
    This is needed since Filters do NOT get inherited from parent logger to child logger.
    See: https://docs.python.org/3/library/logging.html#filter-objects
    """
    logger = logging.getLogger(loggerName)
    subLoggerNames = loggerName.split(".")
    filterList = []
    parentLoggerName = ""
    for subLoggerName in subLoggerNames:
        parentLoggerName += subLoggerName
        parentLogger = logging.getLogger(parentLoggerName)
        filterList += parentLogger.filters
        parentLoggerName += "."
    [logger.addFilter(parentFilter) for parentFilter in filterList]
    return logger


def parseTarget(target: str) -> Tuple[str, int]:
    """
    Parse a target host:port and return components. Port is optional.
    """
    if ":" in target:
        targetHost = target[: target.index(":")]
        targetPort = int(target[target.index(":") + 1:])
    else:
        targetHost = target
        targetPort = 3389
    return targetHost, targetPort


def validateKeyAndCertificate(private_key: str, certificate: str) -> Tuple[str, str]:
    if (private_key is None) != (certificate is None):
        sys.stderr.write("You must provide both the private key and the certificate")
        sys.exit(1)
    elif private_key is None:
        key, cert = getSSLPaths()
        handleKeyAndCertificate(key, cert)
    else:
        key, cert = private_key, certificate

    try:
        # Check if OpenSSL accepts the private key and certificate.
        ServerTLSContext(key, cert)
    except OpenSSL.SSL.Error as error:
        from pyrdp.logging import log
        log.error(
            "An error occurred when creating the server TLS context. " +
            "There may be a problem with your private key or certificate (e.g: signature algorithm too weak). " +
            "Here is the exception: %(error)s",
            {"error": error}
        )
        sys.exit(1)

    return key, cert

def handleKeyAndCertificate(key: str, certificate: str):
    """
    Handle the certificate and key arguments that were given on the command line.
    :param key: path to the TLS private key.
    :param certificate: path to the TLS certificate.
    """

    from pyrdp.logging import LOGGER_NAMES
    logger = logging.getLogger(LOGGER_NAMES.MITM)

    if os.path.exists(key) and os.path.exists(certificate):
        logger.info("Using existing private key: %(privateKey)s", {"privateKey": key})
        logger.info("Using existing certificate: %(certificate)s", {"certificate": certificate})
    else:
        logger.info("Generating a private key and certificate for SSL connections")

        if generateCertificate(key, certificate):
            logger.info("Private key path: %(privateKeyPath)s", {"privateKeyPath": key})
            logger.info("Certificate path: %(certificatePath)s", {"certificatePath": certificate})
        else:
            logger.error("Generation failed. Please provide the private key and certificate with -k and -c")


def getSSLPaths() -> (str, str):
    """
    Get the path to the TLS key and certificate in pyrdp's config directory.
    :return: the path to the key and the path to the certificate.
    """
    config = appdirs.user_config_dir("pyrdp", "pyrdp")

    if not os.path.exists(config):
        os.makedirs(config)

    key = config + "/private_key.pem"
    certificate = config + "/certificate.pem"
    return key, certificate


def generateCertificate(keyPath: str, certificatePath: str) -> bool:
    """
    Generate an RSA private key and certificate with default values.
    :param keyPath: path where the private key should be saved.
    :param certificatePath: path where the certificate should be saved.
    :return: True if generation was successful
    """

    if os.name != "nt":
        nullDevicePath = "/dev/null"
    else:
        nullDevicePath = "NUL"

    result = os.system("openssl req -newkey rsa:2048 -nodes -keyout %s -x509 -days 365 -out %s -subj \"/CN=www.example.com/O=PYRDP/C=US\" 2>%s" % (keyPath, certificatePath, nullDevicePath))
    return result == 0
