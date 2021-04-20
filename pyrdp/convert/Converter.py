#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from pathlib import Path


class Converter:
    def __init__(self, inputFile: Path, outputPrefix: str, format: str):
        self.inputFile = inputFile
        self.outputPrefix = outputPrefix
        self.format = format

    def process(self):
        raise NotImplementedError("Converter.process is not implemented")
