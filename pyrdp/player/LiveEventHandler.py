#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from logging import LoggerAdapter
from pathlib import Path, PosixPath
from typing import BinaryIO, Dict, Union

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QTextEdit

from pyrdp.enum import DeviceType, PlayerPDUType
from pyrdp.layer import PlayerLayer
from pyrdp.pdu import PlayerDeviceMappingPDU, PlayerDirectoryListingRequestPDU, PlayerDirectoryListingResponsePDU, \
    PlayerFileDownloadCompletePDU, PlayerFileDownloadRequestPDU, PlayerFileDownloadResponsePDU, PlayerPDU
from pyrdp.parser import ClientConnectionParser
from pyrdp.player import LiveTab
from pyrdp.player.FileDownloadDialog import FileDownloadDialog
from pyrdp.player.filesystem import DirectoryObserver, Directory, Drive, File, FileSystem, FileSystemItemType
from pyrdp.player.PlayerEventHandler import PlayerEventHandler
from pyrdp.ui import QRemoteDesktop

import os

class LiveEventHandler(PlayerEventHandler, DirectoryObserver):
    """
    Event handler used for live connections. Handles the same events as the replay handler, plus directory listing and
    file read events. Also dispatches download requested by the player.
    """

    addIconToTab = Signal(object)
    connectionClosed = Signal(object)
    renameTab = Signal(object, str)

    def __init__(self, viewer: QRemoteDesktop, text: QTextEdit, log: LoggerAdapter, fileSystem: FileSystem, layer: PlayerLayer, tabInstance: LiveTab):
        super().__init__(viewer, text)
        self.log = log
        self.fileSystem = fileSystem
        self.layer = layer
        self.drives: Dict[int, Drive] = {}
        self.downloadDirectories: Dict[str, Directory] = {}
        self.downloadFiles: Dict[str, BinaryIO] = {}
        self.downloadDialogs: Dict[str, FileDownloadDialog] = {}
        self.tabInstance = tabInstance

        # Clicking on an item and "downloading" is a job. Only one job at a time.
        # We need to process each job independently to keep the dialog reliable
        self.jobsQueue = set()
        self.directoryDownloadQueue = set()
        self.fileDownloadQueue = set()
        self.currentDownload = None

        self.handlers[PlayerPDUType.DIRECTORY_LISTING_RESPONSE] = self.handleDirectoryListingResponse
        self.handlers[PlayerPDUType.FILE_DOWNLOAD_RESPONSE] = self.handleDownloadResponse
        self.handlers[PlayerPDUType.FILE_DOWNLOAD_COMPLETE] = self.handleDownloadComplete
        self.handlers[PlayerPDUType.CLIENT_DATA] = self.onClientData
        self.handlers[PlayerPDUType.CONNECTION_CLOSE] = self.onConnectionClose


    def onClientData(self, pdu: PlayerPDU):
        """
        Message the LiveWindow to rename the tab to the hostname of the client
        """

        clientDataPDU = ClientConnectionParser().parse(pdu.payload)
        clientName = clientDataPDU.coreData.clientName.strip("\x00")

        self.renameTab.emit(self.tabInstance, clientName)
        super().onClientData(pdu)


    def onConnectionClose(self, pdu: PlayerPDU):
        """
        Message the LiveWindow that this tab's connection is closed
        """

        self.connectionClosed.emit(self.tabInstance)
        super().onConnectionClose(pdu)

    def onDeviceMapping(self, pdu: PlayerDeviceMappingPDU):
        super().onDeviceMapping(pdu)

        if pdu.deviceType == DeviceType.RDPDR_DTYP_FILESYSTEM:
            self.addIconToTab.emit(self.tabInstance)
            drive = self.fileSystem.addDrive(pdu.name, pdu.deviceID)
            drive.addObserver(self)
            self.drives[drive.deviceID] = drive

    def onListDirectory(self, deviceID: int, path: str):
        request = PlayerDirectoryListingRequestPDU(self.layer.getCurrentTimeStamp(), deviceID, path)
        self.layer.sendPDU(request)

    def addToDownloadQueue(self, item: Union[File, Directory], targetPath: str, dialog: FileDownloadDialog):
        job = (item, targetPath, dialog)

        self.jobsQueue.add(job)

        if self.currentDownload == None:
            self.dispatchDownload()

    def dispatchDownload(self):
        """
        Since the download is single-threaded, we need to queue everything.
        When requesting the download of a file, it gets queued in fileDownloadQueue.
        When requesting the download of a directory, it gets queued in directoryDownloadQueue.

        When flagging a directory for download, we queue all of his files and directory for download.
        We then download each file of a directory before enumerating other directories.
        When we're done with both file and directories, we start an other queued job
        """

        # Request download of a queued file
        if len(self.fileDownloadQueue) != 0:
            file, savePath, dialog = self.fileDownloadQueue.pop()

            self.currentDownload = file.getFullPath()
            self.onFileDownloadRequested(file, savePath, dialog)

        # Request download of a queued directory
        elif len(self.directoryDownloadQueue) != 0:
            directory, path, dialog = self.directoryDownloadQueue.pop()

            self.currentDownload = directory.getFullPath()
            self.onDirectoryDownloadRequested(directory, path, dialog)

        # Process queued jobs
        elif len(self.jobsQueue) != 0:
            item, path, dialog = self.jobsQueue.pop()
            self.currentDownload = item.getFullPath()

            if isinstance(item, File):
                self.onFileDownloadRequested(item, path, dialog)

            elif isinstance(item, Directory):
                self.onDirectoryDownloadRequested(item, path, dialog)
        else:
            self.currentDownload = None

    def handleDirectoryListingResponse(self, response: PlayerDirectoryListingResponsePDU):
        """
        List the files and subdirectories of a directory.

        If any files or subdirectories have been requested for download,
        we queue them in the appropriate download queue.

        Otherwise, update the directory list.
        """

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
                # If the directory is not flagged as downloading, but the parent is
                if not self.downloadDirectories.get(str(path)) and self.downloadDirectories.get(str(path.parent)):
                    # Create directory on disk
                    parentPath = self.downloadDirectories[str(path.parent)]
                    directoryPath = f"{parentPath}/{fileName}"

                    os.mkdir(directoryPath)

                    # Queue downloads requests
                    directory = Directory(fileName, currentDirectory)
                    dialog = self.downloadDialogs[str(path.parent)]
                    self.directoryDownloadQueue.add((directory, directoryPath, dialog))
                else:
                    currentDirectory.addDirectory(fileName)
            else:
                # If the directory is flagged as download, download the file
                if self.downloadDirectories.get(str(path.parent)):
                    # Create file on disk
                    parentPath = self.downloadDirectories[str(path.parent)]
                    filePath = f"{parentPath}/{fileName}"

                    file = File(fileName, currentDirectory)

                    # Queue downloads requests
                    dialog = self.downloadDialogs[str(path.parent)]
                    dialog.incrementDownloadTotal()
                    self.fileDownloadQueue.add((file, filePath, dialog))
                else:
                    currentDirectory.addFile(fileName)

        # Having 10 files means another chunk is coming, wait for it
        if len(response.fileDescriptions) != 10:
            self.dispatchDownload()

    def onFileDownloadRequested(self, file: File, targetPath: str, dialog: FileDownloadDialog):
        """
        Create the file on disk and request it for download to the client.
        """

        remotePath = file.getFullPath()

        self.log.info("Saving %(remotePath)s to %(targetPath)s", {"remotePath": remotePath, "targetPath": targetPath})

        if file.parent is None:
            self.log.error("Cannot save file without drive information.")
            return

        parent = file.getRootParent()

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

        pdu = PlayerFileDownloadRequestPDU(self.layer.getCurrentTimeStamp(), parent.deviceID, remotePath)
        self.layer.sendPDU(pdu)

    def onDirectoryDownloadRequested(self, directory: Directory, targetPath: str, dialog: FileDownloadDialog):
        """
        Flag the requested directory for download and request to list his files and subdirectories.
        Each of the files and subdirectories will be queued for download.
        """

        remotePath = directory.getFullPath()

        if directory.parent is None:
            self.log.error("Cannot save directory without drive information.")
            return

        parent = directory.getRootParent()

        if parent.type != FileSystemItemType.Drive:
            self.log.error("Cannot save directory: root parent is not a drive.")
            return

        self.downloadDirectories[remotePath] = targetPath
        self.downloadDialogs[remotePath] = dialog

        pdu = PlayerDirectoryListingRequestPDU(self.layer.getCurrentTimeStamp(), parent.deviceID, remotePath)
        self.layer.sendPDU(pdu)

    def handleDownloadResponse(self, response: PlayerFileDownloadResponsePDU):
        """
        Write the received data to the file being downloaded and update the dialog's download progress.
        """

        remotePath = response.path

        if remotePath not in self.downloadFiles:
            return

        targetFile = self.downloadFiles[remotePath]
        targetFile.write(response.payload)

        dialog = self.downloadDialogs[remotePath]
        dialog.reportProgress(len(response.payload))

    def handleDownloadComplete(self, response: PlayerFileDownloadCompletePDU):
        """
        Update the download dialog and remove the file from the list of files to be downloaded.
        """

        remotePath = response.path

        if remotePath not in self.downloadFiles:
            return

        targetFile = self.downloadFiles.pop(remotePath)
        targetFileName = targetFile.name
        targetFile.close()

        dialog = self.downloadDialogs.pop(remotePath)
        dialog.incrementDownloadCount()

        # Report completion if there are no more queued jobs (multiple download)
        # or if no one else uses this dialog (single download)
        if len(self.fileDownloadQueue) == 0 and len(self.directoryDownloadQueue) == 0:
            dialog.reportCompletion(response.error)
            self.downloadDirectories.clear()

        if response.error != 0:
            self.log.error("Error happened when downloading %(remotePath)s. The file may not have been saved completely. Error code: %(errorCode)s", {
                "remotePath": remotePath,
                "errorCode": "0x%08lx" % response.error,
            })

            try:
                Path(targetFileName).unlink()
            except Exception as e:
                self.log.error("Error when deleting file %(path)s: %(exception)s", {"path": targetFileName, "exception": str(e)})
        else:
            self.log.info("Download %(path)s complete.", {"path": targetFile.name})
            self.dispatchDownload()
