#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import argparse
import asyncio
import logging
import logging.handlers
import os
import random
import sys
from pathlib import Path

from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())

from pyrdp.mitm import MITMConfig, RDPMITM

import appdirs
import names
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from pyrdp.core import getLoggerPassFilters
from pyrdp.logging import JSONFormatter, log, LOGGER_NAMES, SensorFilter


class MITMServerFactory(ServerFactory):
    def __init__(self, config: MITMConfig):
        """
        :param config: the MITM configuration
        """
        self.config = config

    def buildProtocol(self, addr):
        sessionId = f"{names.get_first_name()}{random.randrange(100000,999999)}"
        logger = getLoggerPassFilters(f"{LOGGER_NAMES.MITM_CONNECTIONS}.{sessionId}")
        mitm = RDPMITM(logger, self.config)

        return mitm.getProtocol()


def getSSLPaths():
    config = appdirs.user_config_dir("pyrdp", "pyrdp")

    if not os.path.exists(config):
        os.makedirs(config)

    key = config + "/private_key.pem"
    certificate = config + "/certificate.pem"
    return key, certificate


def generateCertificate(keyPath, certificatePath):
    result = os.system("openssl req -newkey rsa:2048 -nodes -keyout %s -x509 -days 365 -out %s -subj '/CN=www.example.com/O=PYRDP/C=US' 2>/dev/null" % (keyPath, certificatePath))
    return result == 0


def prepare_loggers(logLevel, sensorID):
    """
    Sets up the "mitm" and the "mitm.connections" loggers.
    """
    log.prepare_pyrdp_logger(logLevel)
    log.prepare_ssl_session_logger()

    if not os.path.exists("log"):
        os.makedirs("log")

    mitm_logger = getLoggerPassFilters(LOGGER_NAMES.MITM)
    mitm_logger.setLevel(logLevel)

    mitm_connections_logger = getLoggerPassFilters(LOGGER_NAMES.MITM_CONNECTIONS)
    mitm_connections_logger.setLevel(logLevel)

    formatter = log.get_formatter()

    stream_handler = logging.StreamHandler()
    file_handler = logging.handlers.TimedRotatingFileHandler("log/mitm.log", when="D")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    mitm_logger.addHandler(stream_handler)
    mitm_logger.addHandler(file_handler)

    # Make sure that the library writes to the file as well
    pyrdp_logger = log.get_logger()
    pyrdp_logger.addHandler(file_handler)

    exceptions_logger = getLoggerPassFilters(LOGGER_NAMES.PYRDP_EXCEPTIONS)
    exceptions_logger.propagate = False
    exceptions_logger.addHandler(file_handler)

    jsonFormatter = JSONFormatter()
    jsonFileHandler = logging.FileHandler("log/mitm.json")
    sensorFilter = SensorFilter(sensorID)

    jsonFileHandler.setFormatter(jsonFormatter)
    jsonFileHandler.setLevel(logging.INFO)
    jsonFileHandler.addFilter(sensorFilter)

    getLoggerPassFilters(LOGGER_NAMES.MITM_CONNECTIONS).addHandler(jsonFileHandler)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP:port of the target RDP machine (ex: 192.168.1.10:3390)")
    parser.add_argument("-l", "--listen", help="Port number to listen on (default: 3389)", default=3389)
    parser.add_argument("-o", "--output", help="Output folder for replay files", default="pyrdp_output")
    parser.add_argument("-i", "--destination-ip", help="Destination IP address of the PyRDP player.If not specified, RDP events are not sent over the network.")
    parser.add_argument("-d", "--destination-port", help="Listening port of the PyRDP player (default: 3000).", default=3000)
    parser.add_argument("-k", "--private-key", help="Path to private key (for SSL)")
    parser.add_argument("-c", "--certificate", help="Path to certificate (for SSL)")
    parser.add_argument("-n", "--nla", help="For NLA client authentication (need to provide credentials)", action="store_true")
    parser.add_argument("-u", "--username", help="Username that will replace the client's username", default=None)
    parser.add_argument("-p", "--password", help="Password that will replace the client's password", default=None)
    parser.add_argument("-L", "--log-level", help="Log level", default="INFO", choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("-s", "--sensor-id", help="Sensor ID (to differentiate multiple instances of the MITM where logs are aggregated at one place)", default="PyRDP")

    args = parser.parse_args()

    logLevel = getattr(logging, args.log_level)

    prepare_loggers(logLevel, args.sensor_id)
    mitm_log = getLoggerPassFilters(LOGGER_NAMES.MITM)

    target = args.target
    if ":" in target:
        targetHost = target[: target.index(":")]
        targetPort = int(target[target.index(":") + 1:])
    else:
        targetHost = target
        targetPort = 3389
    if (args.private_key is None) != (args.certificate is None):
        mitm_log.error("You must provide both the private key and the certificate")
        sys.exit(1)
    elif args.private_key is None:
        key, certificate = getSSLPaths()
        handleKeyAndCertificate(certificate, key, mitm_log)
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
    config.outDir = Path(args.output)

    reactor.listenTCP(listenPort, MITMServerFactory(config))
    mitm_log.info("MITM Server listening on port %(port)d", {"port": listenPort})
    reactor.run()


def handleKeyAndCertificate(certificate, key, mitm_log):
    if os.path.exists(key) and os.path.exists(certificate):
        mitm_log.info("Using existing private key: %(privateKey)s", {"privateKey": key})
        mitm_log.info("Using existing certificate: %(certificate)s", {"certificate": certificate})
    else:
        mitm_log.info("Generating a private key and certificate for SSL connections")

        if generateCertificate(key, certificate):
            mitm_log.info("Private key path: %(privateKeyPath)s", {"privateKeyPath": key})
            mitm_log.info("Certificate path: %(certificatePath)s", {"certificatePath": certificate})
        else:
            mitm_log.error("Generation failed. Please provide the private key and certificate with -k and -c")


if __name__ == "__main__":
    main()
