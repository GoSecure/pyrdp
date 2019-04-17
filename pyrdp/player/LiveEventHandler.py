#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from pathlib import PosixPath
from typing import Dict

from PySide2.QtWidgets import QTextEdit

from pyrdp.enum import DeviceType, PlayerPDUType
from pyrdp.layer import PlayerLayer
from pyrdp.pdu import PlayerDeviceMappingPDU, PlayerDirectoryListingRequestPDU, PlayerDirectoryListingResponsePDU
from pyrdp.player.filesystem import DirectoryObserver, Drive, FileSystem
from pyrdp.player.PlayerEventHandler import PlayerEventHandler
from pyrdp.ui import QRemoteDesktop


class LiveEventHandler(PlayerEventHandler, DirectoryObserver):
    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit, fileSystem: FileSystem, layer: PlayerLayer):
        super().__init__(viewer, text)
        self.fileSystem = fileSystem
        self.layer = layer
        self.drives: Dict[int, Drive] = {}

        self.handlers[PlayerPDUType.DIRECTORY_LISTING_RESPONSE] = self.handleDirectoryListingResponse

    def onDeviceMapping(self, pdu: PlayerDeviceMappingPDU):
        super().onDeviceMapping(pdu)

        if pdu.deviceType == DeviceType.RDPDR_DTYP_FILESYSTEM:
            drive = self.fileSystem.addDrive(pdu.name, pdu.deviceID)
            drive.addObserver(self)
            self.drives[drive.deviceID] = drive

    def onListDirectory(self, deviceID: int, path: str):
        request = PlayerDirectoryListingRequestPDU(self.layer.getCurrentTimeStamp(), deviceID, path)
        self.layer.sendPDU(request)

    def handleDirectoryListingResponse(self, response: PlayerDirectoryListingResponsePDU):
        for description in response.fileDescriptions:
            path = PosixPath(description.path)
            parts = path.parts
            directoryNames = list(parts[1 : -1])
            fileName = path.name

            if fileName in ["", ".", ".."]:
                continue

            drive = self.drives[response.deviceID]

            currentDirectory = drive
            while len(directoryNames) > 0:
                currentName = directoryNames.pop(0)

                newDirectory = None

                for directory in drive.directories:
                    if directory.name == currentName:
                        newDirectory = directory
                        break

                if newDirectory is None:
                    return

                currentDirectory = newDirectory

            if description.isDirectory:
                currentDirectory.addDirectory(fileName)
            else:
                currentDirectory.addFile(fileName)