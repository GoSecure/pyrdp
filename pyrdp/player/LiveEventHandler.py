#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from logging import LoggerAdapter
from pathlib import Path, PosixPath
from typing import BinaryIO, Dict

from PySide2.QtWidgets import QTextEdit

from pyrdp.enum import DeviceType, PlayerPDUType
from pyrdp.layer import PlayerLayer
from pyrdp.pdu import PlayerDeviceMappingPDU, PlayerDirectoryListingRequestPDU, PlayerDirectoryListingResponsePDU, \
    PlayerFileDownloadCompletePDU, PlayerFileDownloadRequestPDU, PlayerFileDownloadResponsePDU
from pyrdp.player.FileDownloadDialog import FileDownloadDialog
from pyrdp.player.filesystem import DirectoryObserver, Drive, File, FileSystem, FileSystemItemType
from pyrdp.player.PlayerEventHandler import PlayerEventHandler
from pyrdp.ui import QRemoteDesktop


class LiveEventHandler(PlayerEventHandler, DirectoryObserver):
    """
    Event handler used for live connections. Handles the same events as the replay handler, plus directory listing and
    file read events.
    """

    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit, log: LoggerAdapter, fileSystem: FileSystem, layer: PlayerLayer):
        super().__init__(viewer, text)
        self.log = log
        self.fileSystem = fileSystem
        self.layer = layer
        self.drives: Dict[int, Drive] = {}
        self.downloadFiles: Dict[str, BinaryIO] = {}
        self.downloadDialogs: Dict[str, FileDownloadDialog] = {}

        self.handlers[PlayerPDUType.DIRECTORY_LISTING_RESPONSE] = self.handleDirectoryListingResponse
        self.handlers[PlayerPDUType.FILE_DOWNLOAD_RESPONSE] = self.handleDownloadResponse
        self.handlers[PlayerPDUType.FILE_DOWNLOAD_COMPLETE] = self.handleDownloadComplete

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

                for directory in currentDirectory.directories:
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

    def onFileDownloadRequested(self, file: File, targetPath: str, dialog: FileDownloadDialog):
        remotePath = file.getFullPath()

        self.log.info("Saving %(remotePath)s to %(targetPath)s", {"remotePath": remotePath, "targetPath": targetPath})
        parent = file.parent

        if parent is None:
            self.log.error("Cannot save file without drive information.")
            return

        while parent.parent is not None:
            parent = parent.parent

        if parent.type != FileSystemItemType.Drive:
            self.log.error("Cannot save file: root parent is not a drive.")
            return

        try:
            targetFile = open(targetPath, "wb")
        except Exception as e:
            self.log.error("Cannot save file: %(exception)s", {"exception": str(e)})
            return

        self.downloadFiles[remotePath] = targetFile
        self.downloadDialogs[remotePath] = dialog

        pdu = PlayerFileDownloadRequestPDU(self.layer.getCurrentTimeStamp(), parent.deviceID, file.getFullPath())
        self.layer.sendPDU(pdu)

    def handleDownloadResponse(self, response: PlayerFileDownloadResponsePDU):
        remotePath = response.path

        if remotePath not in self.downloadFiles:
            return

        targetFile = self.downloadFiles[remotePath]
        targetFile.write(response.payload)

        dialog = self.downloadDialogs[remotePath]
        dialog.reportProgress(response.offset + len(response.payload))

    def handleDownloadComplete(self, response: PlayerFileDownloadCompletePDU):
        remotePath = response.path

        if remotePath not in self.downloadFiles:
            return

        dialog = self.downloadDialogs.pop(remotePath)
        dialog.reportCompletion(response.error)

        targetFile = self.downloadFiles.pop(remotePath)
        targetFileName = targetFile.name
        targetFile.close()

        if response.error != 0:
            self.log.error("Error happened when downloading %(remotePath)s. The file may not have been saved completely. Error code: %(errorCode)s", {
                "remotePath": remotePath,
                "errorCode": "0x%08lx",
            })

            try:
                Path(targetFileName).unlink()
            except Exception as e:
                self.log.error("Error when deleting file %(path)s: %(exception)s", {"path": targetFileName, "exception": str(e)})
        else:
            self.log.info("Download %(path)s complete.", {"path": targetFile.name})