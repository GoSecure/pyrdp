#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.core import settings

from pathlib import Path


"""
The default configuration for the Player.
"""
DEFAULTS =  settings.load(Path(__file__).parent.absolute() / "player.default.ini")
