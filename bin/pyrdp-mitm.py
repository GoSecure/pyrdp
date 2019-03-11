#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio

from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())

import argparse
import logging
import logging.handlers
import os
import random
import sys
from pathlib import Path

import appdirs
import names
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from pyrdp.logging import JSONFormatter, log, LOGGER_NAMES, SessionLogger, VariableFormatter
from pyrdp.mitm import MITMConfig, RDPMITM


class MITMServerFactory(ServerFactory):
    """
    Server factory for the RDP man-in-the-middle that generates a unique session ID for every connection.
    """

    def __init__(self, config: MITMConfig):
        """
        :param config: the MITM configuration
        """
        self.config = config

    def buildProtocol(self, addr):
        sessionID = f"{names.get_first_name()}{random.randrange(100000,999999)}"
        logger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
        logger = SessionLogger(logger, sessionID)
        mitm = RDPMITM(logger, self.config)

        return mitm.getProtocol()


def prepareLoggers(logLevel: int, sensorID: str, outDir: Path):
    logDir = outDir / "logs"
    logDir.mkdir(exist_ok = True)

    formatter = VariableFormatter("[{asctime}] - {levelname} - {sessionID} - {name} - {message}", style = "{", defaultVariables = {
        "sessionID": "GLOBAL"
    })

    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    streamHandler.setLevel(logLevel)

    logFileHandler = logging.handlers.TimedRotatingFileHandler(logDir / "mitm.log", when = "D")
    logFileHandler.setFormatter(formatter)

    jsonFileHandler = logging.FileHandler(logDir / "mitm.json")
    jsonFileHandler.setFormatter(JSONFormatter({"sensor": sensorID}))
    jsonFileHandler.setLevel(logging.INFO)

    rootLogger = logging.getLogger(LOGGER_NAMES.PYRDP)
    rootLogger.addHandler(streamHandler)
    rootLogger.addHandler(logFileHandler)
    rootLogger.setLevel(logging.DEBUG)

    connectionsLogger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
    connectionsLogger.addHandler(jsonFileHandler)

    log.prepareSSLLogger(logDir / "ssl.log")


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

    result = os.system("openssl req -newkey rsa:2048 -nodes -keyout %s -x509 -days 365 -out %s -subj '/CN=www.example.com/O=PYRDP/C=US' 2>/dev/null" % (keyPath, certificatePath))
    return result == 0


def handleKeyAndCertificate(key: str, certificate: str):
    """
    Handle the certificate and key arguments that were given on the command line.
    :param key: path to the TLS private key.
    :param certificate: path to the TLS certificate.
    """

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


def logConfiguration(config: MITMConfig):
    logging.getLogger(LOGGER_NAMES.MITM).info("Target: %(target)s:%(port)d", {"target": config.targetHost, "port": config.targetPort})
    logging.getLogger(LOGGER_NAMES.MITM).info("Output directory: %(outputDirectory)s", {"outputDirectory": config.outDir.absolute()})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP:port of the target RDP machine (ex: 192.168.1.10:3390)")
    parser.add_argument("-l", "--listen", help="Port number to listen on (default: 3389)", default=3389)
    parser.add_argument("-o", "--output", help="Output folder", default="pyrdp_output")
    parser.add_argument("-i", "--destination-ip", help="Destination IP address of the PyRDP player.If not specified, RDP events are not sent over the network.")
    parser.add_argument("-d", "--destination-port", help="Listening port of the PyRDP player (default: 3000).", default=3000)
    parser.add_argument("-k", "--private-key", help="Path to private key (for SSL)")
    parser.add_argument("-c", "--certificate", help="Path to certificate (for SSL)")
    parser.add_argument("-n", "--nla", help="For NLA client authentication (need to provide credentials)", action="store_true")
    parser.add_argument("-u", "--username", help="Username that will replace the client's username", default=None)
    parser.add_argument("-p", "--password", help="Password that will replace the client's password", default=None)
    parser.add_argument("-L", "--log-level", help="Console logging level. Logs saved to file are always verbose.", default="INFO", choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("-s", "--sensor-id", help="Sensor ID (to differentiate multiple instances of the MITM where logs are aggregated at one place)", default="PyRDP")

    args = parser.parse_args()
    outDir = Path(args.output)
    outDir.mkdir(exist_ok = True)

    logLevel = getattr(logging, args.log_level)

    prepareLoggers(logLevel, args.sensor_id, outDir)
    pyrdpLogger = logging.getLogger(LOGGER_NAMES.MITM)

    target = args.target

    if ":" in target:
        targetHost = target[: target.index(":")]
        targetPort = int(target[target.index(":") + 1:])
    else:
        targetHost = target
        targetPort = 3389

    if (args.private_key is None) != (args.certificate is None):
        pyrdpLogger.error("You must provide both the private key and the certificate")
        sys.exit(1)
    elif args.private_key is None:
        key, certificate = getSSLPaths()
        handleKeyAndCertificate(key, certificate)
    else:
        key, certificate = args.private_key, args.certificate

    listenPort = int(args.listen)

    config = MITMConfig()
    config.targetHost = targetHost
    config.targetPort = targetPort
    config.privateKeyFileName = key
    config.certificateFileName = certificate
    config.attackerHost = args.destination_ip
    config.attackerPort = int(args.destination_port)
    config.replacementUsername = args.username
    config.replacementPassword = args.password
    config.outDir = outDir

    logConfiguration(config)

    reactor.listenTCP(listenPort, MITMServerFactory(config))
    pyrdpLogger.info("MITM Server listening on port %(port)d", {"port": listenPort})
    reactor.run()

    pyrdpLogger.info("MITM terminated")
    logConfiguration(config)

if __name__ == "__main__":
    main()
