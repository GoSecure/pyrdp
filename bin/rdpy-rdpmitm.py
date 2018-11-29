#!/usr/bin/python3
import argparse
import logging
import logging.handlers
import os
import random
import sys
from itertools import cycle

import appdirs
import names
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from rdpy.core import log
from rdpy.mitm.server import MITMServer


class MITMServerFactory(ServerFactory):
    def __init__(self, targetHost, targetPort, privateKeyFileName, certificateFileName, destination_ip, destination_port):
        """
        :param targetHost: The IP that points to the RDP server
        :param targetPort: The port that points to the RDP server
        :param privateKeyFileName: The private key to use for SSL
        :param certificateFileName: The certificate to use for SSL
        :param destination_ip: The IP to which send RDP traffic (for live player).
        :param destination_port: The port to which send RDP traffic (for live player).
        """
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.privateKeyFileName = privateKeyFileName
        self.certificateFileName = certificateFileName
        self.destination_ip = destination_ip
        self.destination_port = destination_port

    def buildProtocol(self, addr):
        server = MITMServer(names.get_first_name(), self.targetHost, self.targetPort, self.certificateFileName,
                            self.privateKeyFileName, self.destination_ip, self.destination_port)
        return server.getProtocol()


def getSSLPaths():
    config = appdirs.user_config_dir("rdpy", "rdpy")

    if not os.path.exists(config):
        os.makedirs(config)

    key = config + "/private_key.pem"
    certificate = config + "/certificate.pem"
    return key, certificate


def generateCertificate(keyPath, certificatePath):
    result = os.system("openssl req -newkey rsa:2048 -nodes -keyout %s -x509 -days 365 -out %s -subj '/CN=www.example.com/O=RDPY/C=US' 2>/dev/null" % (keyPath, certificatePath))
    return result == 0


def prepare_loggers(logLevel):
    """
        Sets up the "mitm" and the "mitm.connections" loggers.
    """
    log.prepare_rdpy_logger(logLevel)
    log.prepare_ssl_session_logger()

    if not os.path.exists("log"):
        os.makedirs("log")

    mitm_logger = logging.getLogger("mitm")
    mitm_logger.setLevel(logLevel)

    mitm_connections_logger = logging.getLogger("mitm.connections")
    mitm_connections_logger.setLevel(logLevel)

    formatter = logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")

    stream_handler = logging.StreamHandler()
    file_handler = logging.handlers.TimedRotatingFileHandler("log/mitm.log", when="D")
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    mitm_logger.addHandler(stream_handler)
    mitm_logger.addHandler(file_handler)

    # Make sure that the library writes to the file as well
    rdpy_logger = log.get_logger()
    rdpy_logger.addHandler(file_handler)

    exceptions_logger = logging.getLogger("rdpy.exceptions")
    exceptions_logger.propagate = False
    exceptions_logger.addHandler(file_handler)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP:port of the target RDP machine (ex: 129.168.0.2:3390)")
    parser.add_argument("-l", "--listen", help="Port number to listen to. Default 3389", default=3389)
    parser.add_argument("-o", "--output", help="Output folder for .rss files")
    parser.add_argument("-i", "--destination-ip", help="Destination IP address to send RDP events to (for live player)."
                                                       " If not specified, doesn't send the RDP events "
                                                       "over the network.")
    parser.add_argument("-d", "--destination-port", help="Destination port number (for live player). Default 3000",
                        default=3000)
    parser.add_argument("-k", "--private-key", help="Path to private key (for SSL)")
    parser.add_argument("-c", "--certificate", help="Path to certificate (for SSL)")
    parser.add_argument("-r", "--standard-security", help="RDP standard security (XP or server 2003 client or older)",
                        action="store_true")
    parser.add_argument("-n", "--nla", help="For NLA client authentication (need to provide credentials)",
                        action="store_true")
    parser.add_argument("-u", "--username", help="Username to use to connect to the target VM (instead of the username "
                                                 "the client sent)")
    parser.add_argument("-p", "--password", help="Password to use to connect to the target VM (instead of the password "
                                                 "the client sent)")
    parser.add_argument("-L", "--log-level", help="Log level", default="INFO", choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"], nargs="?")

    args = parser.parse_args()

    logLevel = getattr(logging, args.log_level)

    prepare_loggers(logLevel)
    mitm_log = logging.getLogger("mitm")

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

        if os.path.exists(key) and os.path.exists(certificate):
            mitm_log.info("Using existing private key: %s" % key)
            mitm_log.info("Using existing certificate: %s" % certificate)
        else:
            mitm_log.info("Generating a private key and certificate for SSL connections")

            if generateCertificate(key, certificate):
                mitm_log.info("Private key path: %s" % key)
                mitm_log.info("Certificate path: %s" % certificate)
            else:
                mitm_log.error("Generation failed. Please provide the private key and certificate with -k and -c")
    else:
        key, certificate = args.private_key, args.certificate
    listenPort = int(args.listen)
    reactor.listenTCP(listenPort, MITMServerFactory(targetHost, targetPort, key, certificate, args.destination_ip, int(args.destination_port)))
    mitm_log.info("MITM Server listening on port %d" % listenPort)
    reactor.run()


if __name__ == "__main__":
    main()
