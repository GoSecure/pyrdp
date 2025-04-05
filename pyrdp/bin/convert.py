#!/usr/bin/python3

#
# This file is part of the PyRDP project.
# Copyright (C) 2020-2024 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import argparse
import logging
import sys
from importlib.metadata import version
from pathlib import Path

from pyrdp.convert.PCAPConverter import PCAPConverter
from pyrdp.convert.ReplayConverter import ReplayConverter
from pyrdp.convert.utils import HANDLERS, loadSecrets
from pyrdp.player import HAS_GUI


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Path to a .pcap or .pyrdp file. "
                                      "Converting from a .pcap will always extract file transfer artifacts in addition to the actual replay.")
    parser.add_argument(
        "-V",
        "--version",
        help="Show the PyRDP version and exit",
        action="version",
        version=f"PyRDP version v{version('pyrdp-mitm')}"
    )
    parser.add_argument(
        "-l",
        "--list-only",
        help="Print the list of sessions in the capture without processing anything",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--secrets",
        help="Path to the file containing the SSL secrets to decrypt Transport Layer Security.",
    )
    parser.add_argument(
        "-f",
        "--format",
        help="Format of the output",
        choices=HANDLERS.keys(),
        default="replay",
    )
    parser.add_argument(
        "--src",
        help="If specified, limits the converted streams to connections initiated from this address",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--dst",
        help="If specified, limits the converted streams to connections destined to this address",
        action="append",
        default=[],
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Path to write the converted files to. If a file name is specified, it will be used as a prefix, "
        "otherwise the result is output next to the source file with the proper extension. "
        "However if the source of the conversion is a .pcap then this option will create a directory where all files will be stored.",
    )

    args = parser.parse_args()

    if not HAS_GUI and args.format == "mp4":
        sys.stderr.write("Error: MP4 conversion requires the full PyRDP installation.")
        sys.exit(1)
    elif HAS_GUI and args.format == "mp4":
        # Initialize QT because QBitmap will segfault without it (#378, #428)
        from PySide6.QtWidgets import QApplication
        QApplication()

    logging.basicConfig(level=logging.CRITICAL)
    logging.getLogger("scapy").setLevel(logging.ERROR)

    inputFile = Path(args.input)

    if args.output:
        output = Path(args.output)
        # Pcaps create directory structures since they also extract transfered artifacts
        if output.is_dir() or inputFile.suffix in [".pcap"]:
            outputPrefix = str(output.absolute()) + "/"
        else:
            outputPrefix = str(output.parent.absolute() / output.stem) + "-"
    else:
        outputPrefix = ""

    if inputFile.suffix in [".pcap"]:
        secrets = loadSecrets(args.secrets) if args.secrets else None
        converter = PCAPConverter(inputFile, outputPrefix, args.format, secrets=secrets, srcFilter=args.src, dstFilter=args.dst, listOnly=args.list_only)
    elif inputFile.suffix in [".pyrdp"]:
        if args.format == "replay":
            sys.stderr.write("Refusing to convert a replay file to a replay file. Choose another format.")
            sys.exit(1)

        converter = ReplayConverter(inputFile, outputPrefix, args.format)
    else:
        sys.stderr.write("Unknown file extension. (Supported: .pcap, .pyrdp)")
        sys.exit(1)

    exitCode = converter.process()
    sys.exit(exitCode)

if __name__ == "__main__":
    main()
