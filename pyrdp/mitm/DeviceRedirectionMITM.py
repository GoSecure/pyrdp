#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import hashlib
import json
from logging import LoggerAdapter
from pathlib import Path
from typing import Dict

from pyrdp.core import decodeUTF16LE, FileProxy, ObservedBy, Observer, Subject
from pyrdp.enum import CreateOption, DeviceType, FileAccess, IOOperationSeverity
from pyrdp.layer import DeviceRedirectionLayer
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.FileMapping import FileMapping, FileMappingDecoder, FileMappingEncoder
from pyrdp.parser import DeviceRedirectionParser
from pyrdp.pdu import DeviceAnnounce, DeviceCloseRequestPDU, DeviceCreateRequestPDU, DeviceIORequestPDU, \
    DeviceIOResponsePDU, DeviceListAnnounceRequest, DeviceReadRequestPDU, DeviceRedirectionPDU


class DeviceRedirectionMITMObserver(Observer):
    def onDeviceAnnounce(self, device: DeviceAnnounce):
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

        if isinstance(pdu, DeviceIORequestPDU) and destination is self.client:
            self.handleIORequest(pdu)
        elif isinstance(pdu, DeviceIOResponsePDU) and destination is self.server:
            self.handleIOResponse(pdu)
        elif isinstance(pdu, DeviceListAnnounceRequest):
            self.handleDeviceListAnnounceRequest(pdu)

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
            requestPDU = self.currentIORequests[pdu.completionID]
            if pdu.ioStatus >> 30 == IOOperationSeverity.STATUS_SEVERITY_ERROR:
                self.log.warning("Received an IO Response with an error IO status: %(responsePDU)s for request %(requestPDU)s", {"responsePDU": repr(pdu), "requestPDU": repr(requestPDU)})

            if isinstance(requestPDU, DeviceCreateRequestPDU):
                self.handleCreateResponse(requestPDU, pdu)
            elif isinstance(requestPDU, DeviceReadRequestPDU):
                self.handleReadResponse(requestPDU, pdu)
            elif isinstance(requestPDU, DeviceCloseRequestPDU):
                self.handleCloseResponse(requestPDU, pdu)

            self.currentIORequests.pop(pdu.completionID)
        else:
            self.log.error("Received IO response to unknown request #%(completionID)d", {"completionID": pdu.completionID})

    def handleDeviceListAnnounceRequest(self, pdu: DeviceListAnnounceRequest):
        """
        Log mapped devices.
        :param pdu: the device list announce request.
        """

        for device in pdu.deviceList:
            self.log.info("%(deviceName)s mapped with ID %(deviceID)d: %(deviceData)s", {
                "deviceName": DeviceType.getPrettyName(device.deviceType),
                "deviceID": device.deviceID,
                "deviceData": device.preferredDosName.rstrip(b"\x00").decode()
            })

            self.observer.onDeviceAnnounce(device)

    def handleCreateResponse(self, request: DeviceCreateRequestPDU, response: DeviceIOResponsePDU):
        """
        Prepare to intercept a file: create a FileProxy object, which will only create the file when we actually write
        to it. When listing a directory, Windows sends a lot of create requests without actually reading the files. We
        use a FileProxy object to avoid creating a lot of empty files whenever a directory is listed.
        :param request: the device create request
        :param response: the device IO response to the request
        """

        response = DeviceRedirectionParser().parseDeviceCreateResponse(response)

        isFileRead = request.desiredAccess & (FileAccess.GENERIC_READ | FileAccess.FILE_READ_DATA) != 0
        isNotDirectory = request.createOptions & CreateOption.FILE_NON_DIRECTORY_FILE != 0

        if isFileRead and isNotDirectory:
            remotePath = Path(decodeUTF16LE(request.path).rstrip("\x00"))
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


    def handleReadResponse(self, request: DeviceReadRequestPDU, response: DeviceIOResponsePDU):
        """
        Write the data that was read at the appropriate offset in the file proxy.
        :param request: the device read request
        :param response: the device IO response to the request
        """

        if request.fileID in self.openedFiles:
            response = DeviceRedirectionParser().parseDeviceReadResponse(response)
            file = self.openedFiles[request.fileID]
            file.seek(request.offset)
            file.write(response.readData)

            # Save the mapping permanently
            mapping = self.openedMappings[request.fileID]
            fileName = mapping.localPath.name

            if fileName not in self.fileMap:
                self.fileMap[fileName] = mapping
                self.saveMapping()

    def handleCloseResponse(self, request: DeviceCloseRequestPDU, _: DeviceIOResponsePDU):
        """
        Close the file if it was open. Compute the hash of the file, then delete it if we already have a file with the
        same hash.
        :param request: the device close request
        :param _: the device IO response to the request
        """

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