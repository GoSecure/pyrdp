#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pyrdp.player.Replay import Replay
from .BaseEventHandler import BaseEventHandler
from .HeadlessEventHandler import HeadlessEventHandler

# UI-Specific imports. These might fail when UI dependencies are not
# present.
try:
    from pyrdp.player.BaseTab import BaseTab
    from pyrdp.player.BaseWindow import BaseWindow
    from pyrdp.player.LiveTab import LiveTab
    from pyrdp.player.LiveThread import LiveThread
    from pyrdp.player.LiveWindow import LiveWindow
    from pyrdp.player.MainWindow import MainWindow
    from pyrdp.player.QTimerSequencer import QTimerSequencer
    from pyrdp.player.ReplayBar import ReplayBar
    from pyrdp.player.ReplayTab import ReplayTab
    from pyrdp.player.ReplayThread import ReplayThread, ReplayThreadEvent
    from pyrdp.player.ReplayWindow import ReplayWindow
    from pyrdp.player.SeekBar import SeekBar
    HAS_GUI = True
except ModuleNotFoundError:
    HAS_GUI = False
