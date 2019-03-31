#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
from base64 import b64encode

import OpenSSL
from twisted.internet import asyncioreactor

from pyrdp.core.ssl import ServerTLSContext

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

from pyrdp.logging import JSONFormatter, log, LOGGER_NAMES, LoggerNameFilter, SessionLogger, VariableFormatter
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


def prepareLoggers(logLevel: int, logFilter: str, sensorID: str, outDir: Path):
    """
    :param logLevel: log level for the stream handler.
    :param logFilter: logger name to filter on.
    :param sensorID: ID to differentiate between instances of this program in the JSON log.
    :param outDir: output directory.
    """
    logDir = outDir / "logs"
    logDir.mkdir(exist_ok = True)

    formatter = VariableFormatter("[{asctime}] - {levelname} - {sessionID} - {name} - {message}", style = "{", defaultVariables = {
        "sessionID": "GLOBAL"
    })

    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    streamHandler.setLevel(logLevel)
    streamHandler.addFilter(LoggerNameFilter(logFilter))

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
    parser.add_argument("-F", "--log-filter", help="Only show logs from this logger name (accepts '*' wildcards)", default="")
    parser.add_argument("-s", "--sensor-id", help="Sensor ID (to differentiate multiple instances of the MITM where logs are aggregated at one place)", default="PyRDP")
    parser.add_argument("--payload", help="Command to run automatically upon connection", default=None)
    parser.add_argument("--payload-powershell", help="PowerShell command to run automatically upon connection", default=None)
    parser.add_argument("--payload-powershell-file", help="PowerShell script to run automatically upon connection (as -EncodedCommand)", default=None)
    parser.add_argument("--payload-delay", help="Time to wait after a new connection before sending the payload, in milliseconds", default=None)
    parser.add_argument("--payload-duration", help="Amount of time the payload should take to complete, in milliseconds", default=None)
    parser.add_argument("--no-replay", help="Disable replay recording", action="store_true")

    args = parser.parse_args()
    outDir = Path(args.output)
    outDir.mkdir(exist_ok = True)

    logLevel = getattr(logging, args.log_level)

    prepareLoggers(logLevel, args.log_filter, args.sensor_id, outDir)
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
    config.recordReplays = not args.no_replay


    payload = None
    powershell = None

    if int(args.payload is not None) + int(args.payload_powershell is not None) + int(args.payload_powershell_file is not None) > 1:
        pyrdpLogger.error("Only one of --payload, --payload-powershell and --payload-powershell-file may be supplied.")
        sys.exit(1)

    if args.payload is not None:
        payload = args.payload
        pyrdpLogger.info("Using payload: %(payload)s", {"payload": args.payload})
    elif args.payload_powershell is not None:
        powershell = args.payload_powershell
        pyrdpLogger.info("Using powershell payload: %(payload)s", {"payload": args.payload_powershell})
    elif args.payload_powershell_file is not None:
        if not os.path.exists(args.payload_powershell_file):
            pyrdpLogger.error("Powershell file %(path)s does not exist.", {"path": args.payload_powershell_file})
            sys.exit(1)

        try:
            with open(args.payload_powershell_file, "r") as f:
                powershell = f.read()
        except IOError as e:
            pyrdpLogger.error("Error when trying to read powershell file: %(error)s", {"error": e})
            sys.exit(1)

        pyrdpLogger.info("Using payload from powershell file: %(path)s", {"path": args.payload_powershell_file})

    if powershell is not None:
        payload = "powershell -EncodedCommand " + b64encode(powershell.encode("utf-16le")).decode()

    if payload is not None:
        if args.payload_delay is None:
            pyrdpLogger.error("--payload-delay must be provided if a payload is provided.")
            sys.exit(1)

        if args.payload_duration is None:
            pyrdpLogger.error("--payload-duration must be provided if a payload is provided.")
            sys.exit(1)


        try:
            config.payloadDelay = int(args.payload_delay)
        except ValueError:
            pyrdpLogger.error("Invalid payload delay. Payload delay must be an integral number of milliseconds.")
            sys.exit(1)

        if config.payloadDelay < 0:
            pyrdpLogger.error("Payload delay must not be negative.")
            sys.exit(1)

        if config.payloadDelay < 1000:
            pyrdpLogger.warning("You have provided a payload delay of less than 1 second. We recommend you use a slightly longer delay to make sure it runs properly.")


        try:
            config.payloadDuration = int(args.payload_duration)
        except ValueError:
            pyrdpLogger.error("Invalid payload duration. Payload duration must be an integral number of milliseconds.")
            sys.exit(1)

        if config.payloadDuration < 0:
            pyrdpLogger.error("Payload duration must not be negative.")
            sys.exit(1)


        config.payload = payload
    elif args.payload_delay is not None:
        pyrdpLogger.error("--payload-delay was provided but no payload was set.")
        sys.exit(1)


    try:
        # Check if OpenSSL accepts the private key and certificate.
        ServerTLSContext(config.privateKeyFileName, config.certificateFileName)
    except OpenSSL.SSL.Error as error:
        log.error(
            "An error occurred when creating the server TLS context. " +
            "There may be a problem with your private key or certificate (e.g: signature algorithm too weak). " +
            "Here is the exception: %(error)s",
            {"error": error}
        )

        sys.exit(1)

    logConfiguration(config)

    reactor.listenTCP(listenPort, MITMServerFactory(config))
    pyrdpLogger.info("MITM Server listening on port %(port)d", {"port": listenPort})
    reactor.run()

    pyrdpLogger.info("MITM terminated")
    logConfiguration(config)

if __name__ == "__main__":
    main()
