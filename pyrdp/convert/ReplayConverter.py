#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
import sys

from progressbar import ProgressBar, Percentage, Bar, ETA

from pyrdp.convert.Converter import Converter
from pyrdp.convert.utils import createHandler
from pyrdp.enum import PlayerPDUType
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

            # Count time-consuming events for progress bar
            # This provides more accurate ETA since images take much longer to process
            time_consuming_iter = replay.iterTimeConsumingEvents()
            total_time_consuming = len(time_consuming_iter)

            if total_time_consuming > 0:
                # Create progress bar based on time-consuming events only
                widgets = [Percentage(), ' ', Bar(), ' ', ETA()]
                pbar = ProgressBar(widgets=widgets, maxval=total_time_consuming).start()
                time_consuming_count = 0

                # Process ALL events
                for event, _ in replay:
                    handler.onPDUReceived(event)

                    # Update progress only for time-consuming events
                    if event.header in {PlayerPDUType.FAST_PATH_OUTPUT, PlayerPDUType.BITMAP}:
                        time_consuming_count += 1
                        pbar.update(time_consuming_count)

                pbar.finish()
            else:
                # No time-consuming events, just process all without progress bar
                for event, _ in replay:
                    handler.onPDUReceived(event)

            print(f"\n[+] Succesfully wrote '{outputPath}'")
            handler.cleanup()
