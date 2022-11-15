#
# This file is part of the PyRDP project.
# Copyright (C) 2020-2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import unittest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

from pyrdp.enum import CreateOption, FileAccessMask, DeviceRedirectionPacketID, MajorFunction, \
    MinorFunction, NtStatusSeverity
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITM
from pyrdp.pdu import DeviceIOResponsePDU, DeviceRedirectionPDU


def MockIOError():
    ioError = Mock(deviceID = 0, completionID = 0, ioStatus = NtStatusSeverity.STATUS_SEVERITY_ERROR << 30)
    return ioError


class DeviceRedirectionMITMTest(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.server = Mock()
        self.log = Mock()
        self.statCounter = Mock()
        self.state = Mock()
        self.state.config = MagicMock()
        self.state.config.outDir = Path("/tmp")
        self.mitm = DeviceRedirectionMITM(self.client, self.server, self.log, self.statCounter, self.state, Mock())

    @patch("pyrdp.mitm.FileMapping.FileMapping.generate")
    def sendCreateResponse(self, request, response, generate):
        self.mitm.handleCreateResponse(request, response)
        return generate

    def test_stats(self):
        self.mitm.handlePDU = Mock()
        self.mitm.statCounter = StatCounter()

        self.mitm.onClientPDUReceived(Mock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION], 1)
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_CLIENT], 1)

        self.mitm.onServerPDUReceived(Mock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION], 2)
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_SERVER], 1)

        self.mitm.handleIORequest(Mock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_IOREQUEST], 1)

        self.mitm.handleIOResponse(Mock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_IORESPONSE], 1)

        error = MockIOError()
        self.mitm.handleIORequest(error)
        self.mitm.handleIOResponse(error)
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_IOERROR], 1)

        self.mitm.handleCloseResponse(Mock(), Mock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_FILE_CLOSE], 1)

        self.mitm.sendForgedFileRead(Mock(), Mock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_FORGED_FILE_READ], 1)

        self.mitm.sendForgedDirectoryListing(Mock(), MagicMock())
        self.assertEqual(self.mitm.statCounter.stats[STAT.DEVICE_REDIRECTION_FORGED_DIRECTORY_LISTING], 1)

    def test_ioError_showsWarning(self):
        self.log.warning = Mock()
        error = MockIOError()

        self.mitm.handleIORequest(error)
        self.mitm.handleIOResponse(error)
        self.log.warning.assert_called_once()

    def test_deviceListAnnounce_logsDevices(self):
        pdu = Mock()
        pdu.deviceList = [Mock(), Mock(), Mock()]

        self.mitm.observer = Mock()
        self.mitm.handleDeviceListAnnounceRequest(pdu)

        self.assertEqual(self.log.info.call_count, len(pdu.deviceList))
        self.assertEqual(self.mitm.observer.onDeviceAnnounce.call_count, len(pdu.deviceList))

    def test_handleClientLogin_logsCredentials(self):
        creds = "PASSWORD"
        self.log.info = Mock()

        self.state.credentialsCandidate = creds
        self.state.inputBuffer = ""
        self.mitm.handleClientLogin()
        self.log.info.assert_called_once()
        self.assertTrue(creds in self.log.info.call_args[0][1].values())

        self.log.info.reset_mock()
        self.state.credentialsCandidate = ""
        self.state.inputBuffer = creds
        self.mitm.handleClientLogin()
        self.log.info.assert_called_once()
        self.assertTrue(creds in self.log.info.call_args[0][1].values())

        self.mitm.handleClientLogin = Mock()
        pdu = Mock(packetID = DeviceRedirectionPacketID.PAKID_CORE_USER_LOGGEDON)
        pdu.__class__ = DeviceRedirectionPDU

        self.mitm.handlePDU(pdu, self.client)
        self.mitm.handleClientLogin.assert_called_once()

    def test_handleIOResponse_uniqueResponse(self):
        handler = Mock()
        self.mitm.responseHandlers[1234] = handler

        pdu = Mock(deviceID = 0, completionID = 0, majorFunction = 1234, ioStatus = 0)
        self.mitm.handleIORequest(pdu)
        self.mitm.handleIOResponse(pdu)
        handler.assert_called_once()

        # Second response should not go through
        self.mitm.handleIOResponse(pdu)
        handler.assert_called_once()

    def test_handleIOResponse_matchingOnly(self):
        handler = Mock()
        self.mitm.responseHandlers[1234] = handler

        request = Mock(deviceID = 0, completionID = 0)
        matching_response = Mock(deviceID = 0, completionID = 0, majorFunction = 1234, ioStatus = 0)
        bad_completionID = Mock(deviceID = 0, completionID = 1, majorFunction = 1234, ioStatus = 0)
        bad_deviceID = Mock(deviceID = 1, completionID = 0, majorFunction = 1234, ioStatus = 0)

        self.mitm.handleIORequest(request)
        self.mitm.handleIOResponse(matching_response)
        handler.assert_called_once()

        self.mitm.handleIORequest(request)

        self.mitm.handleIOResponse(bad_completionID)
        handler.assert_called_once()
        self.log.error.assert_called_once()
        self.log.error.reset_mock()

        self.mitm.handleIOResponse(bad_deviceID)
        handler.assert_called_once()
        self.log.error.assert_called_once()
        self.log.error.reset_mock()

    def test_handlePDU_hidesForgedResponses(self):
        majorFunction = MajorFunction.IRP_MJ_CREATE
        handler = Mock()
        completionID = self.mitm.sendForgedFileRead(0, "forged")
        request = self.mitm.forgedRequests[(0, completionID)]
        request.handlers[majorFunction] = handler

        self.assertEqual(len(self.mitm.forgedRequests), 1)
        response = Mock(deviceID = 0, completionID = completionID, majorFunction = majorFunction, ioStatus = 0)
        response.__class__ = DeviceIOResponsePDU
        self.mitm.handlePDU(response, self.mitm.server)
        handler.assert_called_once()
        self.mitm.server.sendPDU.assert_not_called()

    def test_handleCreateResponse_createsMapping(self):
        createRequest = Mock(
            deviceID = 0,
            completionID = 0,
            desiredAccess = (FileAccessMask.GENERIC_READ | FileAccessMask.FILE_READ_DATA),
            createOptions = CreateOption.FILE_NON_DIRECTORY_FILE,
            path = "file",
        )
        createResponse = Mock(deviceID = 0, completionID = 0, fileID = 0)

        generate = self.sendCreateResponse(createRequest, createResponse)
        self.assertEqual(len(self.mitm.mappings), 1)
        generate.assert_called_once()

    def test_handleReadResponse_writesData(self):
        request = Mock(
            deviceID = 0,
            completionID = 0,
            fileID = 0,
            desiredAccess = (FileAccessMask.GENERIC_READ | FileAccessMask.FILE_READ_DATA),
            createOptions = CreateOption.FILE_NON_DIRECTORY_FILE,
            path = "file",
        )
        response = Mock(deviceID = 0, completionID = 0, fileID = 0, payload = "test payload")
        self.mitm.saveMapping = Mock()

        self.sendCreateResponse(request, response)
        mapping = list(self.mitm.mappings.values())[0]
        mapping.write = Mock()

        self.mitm.handleReadResponse(request, response)
        mapping.write.assert_called_once()

        # Make sure it checks the file ID
        request.fileID, response.fileID = 1, 1
        self.mitm.handleReadResponse(request, response)
        mapping.write.assert_called_once()

    def test_handleCloseResponse_finalizesMapping(self):
        request = Mock(
            deviceID=0,
            completionID=0,
            fileID=0,
            desiredAccess=(FileAccessMask.GENERIC_READ | FileAccessMask.FILE_READ_DATA),
            createOptions=CreateOption.FILE_NON_DIRECTORY_FILE,
            path="file",
        )
        response = Mock(deviceID=0, completionID=0, fileID=0, payload="test payload")
        self.mitm.saveMapping = Mock()

        self.sendCreateResponse(request, response)
        mapping = list(self.mitm.mappings.values())[0]
        mapping.finalize = Mock()

        self.mitm.handleCloseResponse(request, response)

        mapping.finalize.assert_called_once()

    def test_findNextRequestID_incrementsRequestID(self):
        baseID = self.mitm.findNextRequestID()
        self.mitm.sendForgedFileRead(0, Mock())
        self.assertEqual(self.mitm.findNextRequestID(), baseID + 1)
        self.mitm.sendForgedFileRead(1, Mock())
        self.assertEqual(self.mitm.findNextRequestID(), baseID + 2)

    def test_sendForgedFileRead_failsWhenDisabled(self):
        self.mitm.config.extractFiles = False
        self.assertFalse(self.mitm.sendForgedFileRead(1, "/test"))

    def test_sendForgedDirectoryListing_failsWhenDisabled(self):
        self.mitm.config.extractFiles = False
        self.assertFalse(self.mitm.sendForgedDirectoryListing(1, "/"))


class ForgedRequestTest(unittest.TestCase):
    def setUp(self):
        self.request = DeviceRedirectionMITM.ForgedRequest(0, 0, Mock())

    def test_sendIORequest_sendsToClient(self):
        self.request.sendIORequest(Mock())
        self.request.mitm.client.sendPDU.assert_called_once()

    def test_onCloseResponse_completesRequest(self):
        self.request.onCloseResponse(Mock())
        self.assertTrue(self.request.isComplete)

    def test_onCreateResponse_checksStatus(self):
        self.request.onCreateResponse(Mock(ioStatus = 1))
        self.assertIsNone(self.request.fileID)


class ForgedFileReadRequestTest(unittest.TestCase):
    def setUp(self):
        self.request = DeviceRedirectionMITM.ForgedFileReadRequest(0, 0, Mock(), "file")

    def test_onCreateResponse_sendsReadRequest(self):
        self.request.sendReadRequest = Mock()
        self.request.onCreateResponse(Mock(ioStatus = 0))
        self.request.sendReadRequest.assert_called_once()

    def test_onCreateResponse_completesRequest(self):
        self.request.onCreateResponse(Mock(ioStatus = 1))
        self.request.mitm.observer.onFileDownloadComplete.assert_called_once()
        self.assertTrue(self.request.isComplete)

    def test_handleFileComplete_sendsCloseRequest(self):
        self.request.sendCloseRequest = Mock()
        self.request.fileID = Mock()
        self.request.handleFileComplete(1)
        self.request.sendCloseRequest.assert_called_once()

    def test_onReadResponse_closesOnError(self):
        self.request.fileID = Mock()
        self.request.sendCloseRequest = Mock()
        self.request.mitm.observer.onFileDownloadComplete = Mock()
        self.request.onReadResponse(Mock(ioStatus = 1))
        self.request.sendCloseRequest.assert_called_once()
        self.request.mitm.observer.onFileDownloadComplete.assert_called_once()

    def test_onReadResponse_updatesProgress(self):
        payload = b"testing"
        self.request.sendReadRequest = Mock()
        self.request.mitm.observer.onFileDownloadResult = Mock()
        self.request.onReadResponse(Mock(ioStatus = 0, payload = payload))

        self.assertEqual(self.request.offset, len(payload))
        self.request.mitm.observer.onFileDownloadResult.assert_called_once()
        self.request.sendReadRequest.assert_called_once()

    def test_onReadResponse_closesWhenDone(self):
        self.request.fileID = Mock()
        self.request.sendCloseRequest = Mock()
        self.request.mitm.observer.onFileDownloadComplete = Mock()
        self.request.onReadResponse(Mock(ioStatus = 0, payload = b""))
        self.request.sendCloseRequest.assert_called_once()
        self.request.mitm.observer.onFileDownloadComplete.assert_called_once()


class ForgedDirectoryListingRequestTest(unittest.TestCase):
    def setUp(self):
        self.request = DeviceRedirectionMITM.ForgedDirectoryListingRequest(0, 0, Mock(), "directory")

    def test_send_removesTrailingSlash(self):
        self.request.sendIORequest = Mock()
        self.request.path = "directory\\"

        self.request.send()
        ioRequest = self.request.sendIORequest.call_args[0][0]
        self.assertEqual(ioRequest.path, "directory")

    def test_send_handlesWildcard(self):
        self.request.sendIORequest = Mock()
        self.request.path = "directory\\*"

        self.request.send()
        ioRequest = self.request.sendIORequest.call_args[0][0]
        self.assertEqual(ioRequest.path, "directory")

    def test_send_handlesNormalPath(self):
        self.request.sendIORequest = Mock()
        self.request.send()

        ioRequest = self.request.sendIORequest.call_args[0][0]
        self.request.sendIORequest.assert_called_once()
        self.assertEqual(ioRequest.path, "directory")

    def test_onCreateResponse_completesOnError(self):
        self.request.onCreateResponse(Mock(ioStatus = 1))
        self.assertTrue(self.request.isComplete)

    def test_onCreateResponse_sendsDirectoryRequest(self):
        self.request.sendIORequest = Mock()
        self.request.onCreateResponse(Mock(ioStatus = 0))
        self.request.sendIORequest.assert_called_once()
        self.assertEqual(self.request.sendIORequest.call_args[0][0].majorFunction, MajorFunction.IRP_MJ_DIRECTORY_CONTROL)
        self.assertEqual(self.request.sendIORequest.call_args[0][0].minorFunction, MinorFunction.IRP_MN_QUERY_DIRECTORY)

    def test_onDirectoryControlResponse_completesOnError(self):
        self.request.sendIORequest = Mock()
        self.request.onDirectoryControlResponse(Mock(ioStatus = 1, minorFunction = MinorFunction.IRP_MN_QUERY_DIRECTORY))
        self.request.sendIORequest.assert_called_once()
        self.assertEqual(self.request.sendIORequest.call_args[0][0].majorFunction, MajorFunction.IRP_MJ_CLOSE)
        self.request.mitm.observer.onDirectoryListingComplete.assert_called_once()

    def test_onDirectoryControlResponse_handlesSuccessfulResponse(self):
        self.request.sendIORequest = Mock()
        response = MagicMock(
            ioStatus = 0,
            minorFunction = MinorFunction.IRP_MN_QUERY_DIRECTORY,
            fileInformation = [MagicMock()]
        )

        self.request.onDirectoryControlResponse(response)

        # Sends result to observer
        self.request.mitm.observer.onDirectoryListingResult.assert_called_once()

        # Sends follow-up directory listing request
        self.assertEqual(self.request.sendIORequest.call_args[0][0].majorFunction, MajorFunction.IRP_MJ_DIRECTORY_CONTROL)
        self.assertEqual(self.request.sendIORequest.call_args[0][0].minorFunction, MinorFunction.IRP_MN_QUERY_DIRECTORY)
