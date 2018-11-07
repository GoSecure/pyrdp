#!/usr/bin/env python2
import argparse
import logging
import os
import sys

import appdirs
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory

from rdpy.core import log
from rdpy.mitm.server import MITMServer


class MITMServerFactory(ServerFactory):
    def __init__(self, targetHost, targetPort, privateKeyFileName, certificateFileName):
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.privateKeyFileName = privateKeyFileName
        self.certificateFileName = certificateFileName

    def buildProtocol(self, addr):
        server = MITMServer(self.targetHost, self.targetPort, self.certificateFileName, self.privateKeyFileName)
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


if __name__ == "__main__":
    log.get_logger().setLevel(logging.DEBUG)

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

    args = parser.parse_args()
    target = args.target

    if ":" in target:
        targetHost = target[: target.index(":")]
        targetPort = int(target[target.index(":") + 1 :])
    else:
        targetHost = target
        targetPort = 3389

    if (args.private_key is None) != (args.certificate is None):
        log.error("You must provide both the private key and the certificate")
        sys.exit(1)
    elif args.private_key is None:
        key, certificate = getSSLPaths()

        if os.path.exists(key) and os.path.exists(certificate):
            log.info("Using existing private key: %s" % key)
            log.info("Using existing certificate: %s" % certificate)
        else:
            log.info("Generating a private key and certificate for SSL connections")

            if generateCertificate(key, certificate):
                log.info("Private key path: %s" % key)
                log.info("Certificate path: %s" % certificate)
            else:
                log.error("Generation failed. Please provide the private key and certificate with -k and -c")
    else:
        key, certificate = args.private_key, args.certificate


    listenPort = int(args.listen)
    reactor.listenTCP(listenPort, MITMServerFactory(targetHost, targetPort, key, certificate))
    log.info("MITM Server listening on port %d" % listenPort)
    reactor.run()
