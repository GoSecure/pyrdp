#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import TextIOBase
from sys import stdout

from pyrdp.player import BaseEventHandler


class HeadlessEventHandler(BaseEventHandler):
    """
    Handle events from a replay file without rendering to a surface.

    This event handler does not require any graphical dependencies.
    """

    def __init__(self, output: TextIOBase = stdout):
        super().__init__()
        self.output = output

    def writeText(self, text: str):
        self.output.write(text.rstrip("\x00"))

    def writeSeparator(self):
        self.output.write("\n--------------------\n")

    def onMouseButton(self, buttons, pos):
        pressed = []
        if 1 in buttons and buttons[1]:
            pressed.append('Left')
        if 2 in buttons and buttons[2]:
            pressed.append('Right')
        if 3 in buttons and buttons[3]:
            pressed.append('Middle')

        (x, y) = pos
        self.writeText(f'\n<Click ({", ".join(pressed)}) @ ({x}, {y})>')
