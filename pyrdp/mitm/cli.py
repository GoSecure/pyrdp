#
# This file is part of the PyRDP project.
# Copyright (C) 2020-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
File that contains methods related to the MITM command line.
To be consumed either via bin/pyrdp-mitm.py or via twistd plugin.
"""
import argparse
import logging
import logging.handlers
import os
import sys
from base64 import b64encode
from pathlib import Path
from typing import Tuple

import OpenSSL

from pyrdp.core import settings
from pyrdp.core.ssl import ServerTLSContext
from pyrdp.logging import configure as configureLoggers, LOGGER_NAMES
from pyrdp.mitm.config import DEFAULTS, MITMConfig
from pyrdp.enum import NegotiationProtocols


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
        sys.stderr.write("You must provide both the private key and the certificate\n")
        sys.exit(1)

    if private_key is None:
        # Certificates will be generated automatically.
        return None, None
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


def showConfiguration(config: MITMConfig):
    logging.getLogger(LOGGER_NAMES.MITM).info("Target: %(target)s:%(port)d", {
        "target": config.targetHost, "port": config.targetPort})
    logging.getLogger(LOGGER_NAMES.MITM).info("Output directory: %(outputDirectory)s",
                                              {"outputDirectory": config.outDir.absolute()})


def buildArgParser():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP:port of the target RDP machine (ex: 192.168.1.10:3390)", nargs='?', default=None)
    parser.add_argument("-l", "--listen", help="Port number to listen on (default: 3389)", default=3389)
    parser.add_argument("-o", "--output", help="Output folder", default="pyrdp_output")
    parser.add_argument("-i", "--destination-ip",
                        help="Destination IP address of the PyRDP player.If not specified, RDP events are"
                        " not sent over the network.")
    parser.add_argument("-d", "--destination-port",
                        help="Listening port of the PyRDP player (default: 3000).", default=3000)
    parser.add_argument("-k", "--private-key", help="Specify path to private key (for SSL)")
    parser.add_argument("-c", "--certificate", help="Specify path to certificate (for SSL).")
    parser.add_argument("-u", "--username", help="Username that will replace the client's username", default=None)
    parser.add_argument("-p", "--password", help="Password that will replace the client's password", default=None)
    parser.add_argument("-L", "--log-level", help="Console logging level. Logs saved to file are always verbose.",
                        default="INFO", choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("-F", "--log-filter",
                        help="Only show logs from this logger name (accepts '*' wildcards)", default="")
    parser.add_argument("--auth", help="Specify allowed authentication mechanisms (Comma-separated, choose from: tls, ssp)", default="tls")
    parser.add_argument(
        "-s", "--sensor-id", help="Sensor ID (to differentiate multiple instances of the MITM"
        " where logs are aggregated at one place)")
    parser.add_argument("--payload", help="Command to run automatically upon connection", default=None)
    parser.add_argument("--payload-powershell",
                        help="PowerShell command to run automatically upon connection", default=None)
    parser.add_argument("--payload-powershell-file",
                        help="PowerShell script to run automatically upon connection (as -EncodedCommand)",
                        default=None)
    parser.add_argument(
        "--payload-delay", help="Time to wait after a new connection before sending the payload, in milliseconds",
        default=None)
    parser.add_argument(
        "--payload-duration", help="Amount of time for which input / output should be dropped, in milliseconds."
        " This can be used to hide the payload screen.", default=None)
    parser.add_argument("--disable-active-clipboard",
                        help="Disables the active clipboard stealing to request clipboard content upon connection.",
                        action="store_true")
    parser.add_argument("--crawl", help="Enable automatic shared drive scraping", action="store_true")
    parser.add_argument("--crawler-match-file",
                        help="File to be used by the crawler to chose what to download when scraping the client shared"
                        " drives.", default=None)
    parser.add_argument("--crawler-ignore-file",
                        help="File to be used by the crawler to chose what folders to avoid when scraping the client"
                        " shared drives.", default=None)
    parser.add_argument("--no-replay", help="Disable replay recording", action="store_true")
    parser.add_argument("--no-downgrade", help="Disables downgrading of unsupported extensions. This makes PyRDP harder"
                        " to fingerprint but might impact the player's ability to replay captured traffic.",
                        action="store_true")
    parser.add_argument(
        "--no-files", help="Do not extract files transferred between the client and server.", action="store_true")
    parser.add_argument(
        "--transparent", help="Spoof source IP for connections to the server (See README)", action="store_true")
    parser.add_argument("--no-gdi", help="Disable accelerated graphics pipeline (MS-RDPEGDI) extension",
                        action="store_true")
    parser.add_argument("--nla-redirection-host", help="Redirection target ip if NLA is enforced", default=None)
    parser.add_argument("--nla-redirection-port", help="Redirection target port if NLA is enforced", type=int, default=None)

    return parser


def configure(cmdline=None) -> MITMConfig:
    parser = buildArgParser()

    if cmdline:
        args = parser.parse_args(cmdline)
    else:
        args = parser.parse_args()

    # Load configuration file.
    cfg = settings.load(settings.CONFIG_DIR + '/mitm.ini', DEFAULTS)

    # Override some of the switches based on command line arguments.
    if args.output:
        cfg.set('vars', 'output_dir', args.output)
    if args.log_filter:
        cfg.set('logs', 'filter', args.log_filter)
    if args.log_level:
        cfg.set('vars', 'level', args.log_level)
    if args.sensor_id:
        cfg.set('vars', 'sensor_id', args.sensor_id)

    outDir = Path(cfg.get('vars', 'output_dir'))
    outDir.mkdir(exist_ok=True)

    configureLoggers(cfg)
    logger = logging.getLogger(LOGGER_NAMES.PYRDP)

    if args.target is None and not args.transparent:
        parser.print_usage()
        sys.stderr.write('error: A relay target is required unless running in transparent proxy mode.\n')
        sys.exit(1)

    if (args.nla_redirection_host is None) != (args.nla_redirection_port is None):
        sys.stderr.write('Error: please provide both --nla-redirection-host and --nla-redirection-port\n')
        sys.exit(1)

    if args.target:
        targetHost, targetPort = parseTarget(args.target)
    else:
        targetHost = None
        targetPort = 3389  # FIXME: Allow to set transparent port as well.

    key, certificate = validateKeyAndCertificate(args.private_key, args.certificate)

    config = MITMConfig()
    config.targetHost = targetHost
    config.targetPort = targetPort
    config.privateKeyFileName = key
    config.listenPort = int(args.listen)
    config.certificateFileName = certificate
    config.attackerHost = args.destination_ip
    config.attackerPort = int(args.destination_port)
    config.replacementUsername = args.username
    config.replacementPassword = args.password
    config.outDir = outDir
    config.enableCrawler = args.crawl
    config.crawlerMatchFileName = args.crawler_match_file
    config.crawlerIgnoreFileName = args.crawler_ignore_file
    config.recordReplays = not args.no_replay
    config.downgrade = not args.no_downgrade
    config.transparent = args.transparent
    config.extractFiles = not args.no_files
    config.disableActiveClipboardStealing = args.disable_active_clipboard
    config.useGdi = not args.no_gdi
    config.redirectionHost = args.nla_redirection_host
    config.redirectionPort = args.nla_redirection_port

    payload = None
    powershell = None

    npayloads = int(args.payload is not None) + \
        int(args.payload_powershell is not None) + \
        int(args.payload_powershell_file is not None)

    if npayloads > 1:
        logger.error("Only one of --payload, --payload-powershell and --payload-powershell-file may be supplied.")
        sys.exit(1)

    if args.payload is not None:
        payload = args.payload
        logger.info("Using payload: %(payload)s", {"payload": args.payload})
    elif args.payload_powershell is not None:
        powershell = args.payload_powershell
        logger.info("Using powershell payload: %(payload)s", {"payload": args.payload_powershell})
    elif args.payload_powershell_file is not None:
        if not os.path.exists(args.payload_powershell_file):
            logger.error("Powershell file %(path)s does not exist.", {"path": args.payload_powershell_file})
            sys.exit(1)

        try:
            with open(args.payload_powershell_file, "r") as f:
                powershell = f.read()
        except IOError as e:
            logger.error("Error when trying to read powershell file: %(error)s", {"error": e})
            sys.exit(1)

        logger.info("Using payload from powershell file: %(path)s", {"path": args.payload_powershell_file})

    if powershell is not None:
        payload = "powershell -EncodedCommand " + b64encode(powershell.encode("utf-16le")).decode()

    if payload is not None:
        if args.payload_delay is None:
            logger.error("--payload-delay must be provided if a payload is provided.")
            sys.exit(1)

        if args.payload_duration is None:
            logger.error("--payload-duration must be provided if a payload is provided.")
            sys.exit(1)

        try:
            config.payloadDelay = int(args.payload_delay)
        except ValueError:
            logger.error("Invalid payload delay. Payload delay must be an integral number of milliseconds.")
            sys.exit(1)

        if config.payloadDelay < 0:
            logger.error("Payload delay must not be negative.")
            sys.exit(1)

        if config.payloadDelay < 1000:
            logger.warning(
                "You have provided a payload delay of less than 1 second."
                " We recommend you use a slightly longer delay to make sure it runs properly.")

        try:
            config.payloadDuration = int(args.payload_duration)
        except ValueError:
            logger.error("Invalid payload duration. Payload duration must be an integral number of milliseconds.")
            sys.exit(1)

        if config.payloadDuration < 0:
            logger.error("Payload duration must not be negative.")
            sys.exit(1)

        config.payload = payload
    elif args.payload_delay is not None:
        logger.error("--payload-delay was provided but no payload was set.")
        sys.exit(1)

    # Configure allowed authentication protocols.
    for auth in args.auth.split(','):
        auth = auth.strip()
        if auth == "tls":
            config.authMethods |= NegotiationProtocols.SSL
        elif auth == "ssp":
            # CredSSP implies TLS.
            config.authMethods |= (NegotiationProtocols.SSL | NegotiationProtocols.CRED_SSP)

    showConfiguration(config)
    return config
