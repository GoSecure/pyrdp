#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import sys

from progressbar import progressbar

from pyrdp.convert.Converter import Converter
from pyrdp.convert.utils import createHandler
from pyrdp.player import Replay


class ReplayConverter(Converter):
    def process(self):
        with open(self.inputFile, "rb") as f:
            replay = Replay(f)

            print(f"[*] Converting '{self.inputFile}' to {self.format.upper()}")

            outputFileBase = self.outputPrefix + self.inputFile.stem
            handler, outputPath = createHandler(self.format, outputFileBase)

            if not handler:
                print("The input file is already a replay file. Nothing to do.")
                sys.exit(1)

            for event, _ in progressbar(replay):
                handler.onPDUReceived(event)

            print(f"\n[+] Succesfully wrote '{outputPath}'")
            handler.cleanup()
