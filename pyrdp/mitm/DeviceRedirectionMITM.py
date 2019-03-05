#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import datetime
import hashlib
import json
from logging import LoggerAdapter
from pathlib import Path
from typing import BinaryIO, Dict

import names

from pyrdp.core import decodeUTF16LE
from pyrdp.enum import CreateOption, FileAccess, IOOperationSeverity
from pyrdp.layer import DeviceRedirectionLayer
from pyrdp.mitm.config import MITMConfig
from pyrdp.parser import DeviceRedirectionParser
from pyrdp.pdu import DeviceCloseRequestPDU, DeviceCreateRequestPDU, \
    DeviceIORequestPDU, DeviceIOResponsePDU, DeviceListAnnounceRequest, DeviceReadRequestPDU, DeviceRedirectionPDU


class FileMapping:
    """
    Class containing information for a file intercepted by the DeviceRedirectionMITM.
    """

    def __init__(self, remotePath: Path, localPath: Path, creationTime: datetime.datetime, fileHash: str):
        """
        :param remotePath: the path of the file on the original machine
        :param localPath: the path of the file on the intercepting machine
        :param creationTime: the creation time of the local file
        :param fileHash: the file hash in hex format (empty string if the file is not complete)
        """
        self.remotePath = remotePath
        self.localPath = localPath
        self.creationTime = creationTime
        self.hash: str = fileHash

    @staticmethod
    def generate(remotePath: Path, outDir: Path):
        localName = f"{names.get_first_name()}{names.get_last_name()}"
        creationTime = datetime.datetime.now()

        index = 2
        suffix = ""

        while True:
            if not (outDir / f"{localName}{suffix}").exists():
                break
            else:
                suffix = f"_{index}"
                index += 1

        localName += suffix

        return FileMapping(remotePath, outDir / localName, creationTime, "")


class FileMappingEncoder(json.JSONEncoder):
    """
    JSON encoder for FileMapping objects.
    """

    def default(self, o):
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        elif not isinstance(o, FileMapping):
            return super().default(o)

        return {
            "remotePath": str(o.remotePath),
            "localPath": str(o.localPath),
            "creationTime": o.creationTime,
            "sha1": o.hash
        }


class FileMappingDecoder(json.JSONDecoder):
    """
    JSON decoder for FileMapping objects.
    """

    def __init__(self):
        super().__init__(object_hook=self.decodeFileMapping)

    def decodeFileMapping(self, dct: Dict):
        for key in ["remotePath", "localPath", "creationTime"]:
            if key not in dct:
                return dct

        creationTime = datetime.datetime.strptime(dct["creationTime"], "%Y-%m-%dT%H:%M:%S.%f")
        return FileMapping(Path(dct["remotePath"]), Path(dct["localPath"]), creationTime, dct["sha1"])


class FileProxy:
    """
    Proxy object that waits until a file is accessed before creating it.
    """

    def __init__(self, path: Path, mode: str, mapping: FileMapping, log: LoggerAdapter):
        """
        :param path: path of the file
        :param mode: file opening mode
        :param mapping: FileMapping object for this file
        :param log: logger for this component
        """
        self.path = path
        self.mode = mode
        self.mapping = mapping
        self.log = log
        self.file: BinaryIO = None

    def createFile(self):
        """
        Create the file and overwrite this object's methods with the file object's methods.
        """

        if self.file is None:
            self.log.info("Saving file '%(remotePath)s' to '%(localPath)s'", {"localPath": self.path, "remotePath": self.mapping.remotePath})

            self.file = open(str(self.path), self.mode)
            self.write = self.file.write
            self.seek = self.file.seek
            self.close = self.file.close

    def write(self, *args, **kwargs):
        self.createFile()
        self.file.write(*args, **kwargs)

    def seek(self, *args, **kwargs):
        self.createFile()
        self.file.seek(*args, **kwargs)

    def close(self):
        if self.file is not None:
            self.log.debug("Closing file %(path)s", {"path": self.path})
            self.file.close()


class DeviceRedirectionMITM:
    """
    MITM component for the device redirection channel.
    """

    def __init__(self, client: DeviceRedirectionLayer, server: DeviceRedirectionLayer, log: LoggerAdapter, config: MITMConfig):
        """
        :param client: device redirection layer for the client side
        :param server: device redirection layer for the server side
        :param log: logger for this component
        :param config: MITM configuration
        """

        self.client = client
        self.server = server
        self.log = log
        self.config = config
        self.currentIORequests: Dict[int, DeviceIORequestPDU] = {}
        self.openedFiles: Dict[int, FileProxy] = {}
        self.fileMap: Dict[str, FileMapping] = {}

        try:
            with open(self.filemapFile, "r") as f:
                self.fileMap: Dict[str, FileMapping] = json.loads(f.read(), cls=FileMappingDecoder)
        except IOError:
            pass
        except json.JSONDecodeError:
            self.log.error(f"Failed to decode file mapping, overwriting previous file")

        self.client.createObserver(
            onPDUReceived=self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived=self.onServerPDUReceived,
        )

    @property
    def filemapFile(self) -> str:
        """
        Get the path to the saved file mapping.
        """
        return str(self.config.outDir / "mapping.json")

    def saveMapping(self):
        """
        Save the file mapping to a file in JSON format.
        """

        with open(self.filemapFile, "w") as f:
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

    def handleDeviceListAnnounceRequest(self, pdu: DeviceListAnnounceRequest):
        """
        Log mapped devices.
        :param pdu: the device list announce request.
        """

        for device in pdu.deviceList:
            self.log.info("%(deviceName)s mapped with ID %(deviceID)d: %(deviceData)s", {
                "deviceName": device.deviceType.name,
                "deviceID": device.deviceID,
                "deviceData": device.deviceData.decode(errors="backslashreplace").rstrip("\x00")
            })

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

            localPath = mapping.localPath
            self.openedFiles[response.fileID] = FileProxy(localPath, "wb", mapping, self.log)


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

            self.fileMap[file.mapping.localPath.name] = file.mapping
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

            # Compute the hash for the final file
            with open(str(file.mapping.localPath), "rb") as f:
                sha1 = hashlib.sha1()

                while True:
                    buffer = f.read(65536)

                    if len(buffer) == 0:
                        break

                    sha1.update(buffer)

                file.mapping.hash = sha1.hexdigest()

            # Check if a file with the same hash exists. If so, keep that one and remove the current file.
            for localPath, mapping in self.fileMap.items():
                if mapping is file.mapping:
                    continue

                if mapping.hash == file.mapping.hash:
                    file.mapping.localPath.unlink()
                    self.fileMap.pop(file.mapping.localPath.name)
                    break

            self.saveMapping()