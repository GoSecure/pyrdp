#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from PySide2.QtWidgets import QTextEdit

from pyrdp.core import Directory
from pyrdp.enum import DeviceType
from pyrdp.pdu import PlayerDeviceMappingPDU
from pyrdp.player.PlayerEventHandler import PlayerEventHandler
from pyrdp.ui import QRemoteDesktop


class LiveEventHandler(PlayerEventHandler):
    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit, fileSystem: Directory):
        super().__init__(viewer, text)
        self.fileSystem = fileSystem

    def onDeviceMapping(self, pdu: PlayerDeviceMappingPDU):
        super().onDeviceMapping(pdu)

        if pdu.deviceType == DeviceType.RDPDR_DTYP_FILESYSTEM:
            self.fileSystem.addDirectory(pdu.name)