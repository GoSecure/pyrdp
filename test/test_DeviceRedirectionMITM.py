import unittest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open

from pyrdp.enum import CreateOption, FileAccessMask, IOOperationSeverity, DeviceRedirectionPacketID
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITM
from pyrdp.pdu import DeviceIOResponsePDU, DeviceRedirectionPDU


def MockIOError():
    ioError = Mock(deviceID = 0, completionID = 0, ioStatus = IOOperationSeverity.STATUS_SEVERITY_ERROR << 30)
    return ioError


@patch("builtins.open", new_callable=mock_open)
class DeviceRedirectionMITMTest(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.server = Mock()
        self.log = Mock()
        self.statCounter = Mock()
        self.state = Mock()
        self.state.config = MagicMock()
        self.state.config.outDir = Path("/tmp")
        self.mitm = DeviceRedirectionMITM(self.client, self.server, self.log, self.statCounter, self.state)

    def test_stats(self, *args):
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

    def test_ioError_showsWarning(self, *args):
        self.log.warning = Mock()
        error = MockIOError()

        self.mitm.handleIORequest(error)
        self.mitm.handleIOResponse(error)
        self.log.warning.assert_called_once()

    def test_deviceListAnnounce_logsDevices(self, *args):
        pdu = Mock()
        pdu.deviceList = [Mock(), Mock(), Mock()]

        self.mitm.observer = Mock()
        self.mitm.handleDeviceListAnnounceRequest(pdu)

        self.assertEqual(self.log.info.call_count, len(pdu.deviceList))
        self.assertEqual(self.mitm.observer.onDeviceAnnounce.call_count, len(pdu.deviceList))

    def test_handleClientLogin_logsCredentials(self, *args):
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

    def test_handleIOResponse_uniqueResponse(self, *args):
        handler = Mock()
        self.mitm.responseHandlers[1234] = handler

        pdu = Mock(deviceID = 0, completionID = 0, majorFunction = 1234, ioStatus = 0)
        self.mitm.handleIORequest(pdu)
        self.mitm.handleIOResponse(pdu)
        handler.assert_called_once()

        # Second response should not go through
        self.mitm.handleIOResponse(pdu)
        handler.assert_called_once()

    def test_handleIOResponse_matchingOnly(self, *args):
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

    def test_handlePDU_hidesForgedResponses(self, *args):
        handler = Mock()
        completionID = self.mitm.sendForgedFileRead(0, "forged")
        request = self.mitm.forgedRequests[(0, completionID)]
        request.handlers[1234] = handler

        self.assertEqual(len(self.mitm.forgedRequests), 1)
        response = Mock(deviceID = 0, completionID = completionID, majorFunction = 1234, ioStatus = 0)
        response.__class__ = DeviceIOResponsePDU
        self.mitm.handlePDU(response, self.mitm.server)
        handler.assert_called_once()
        self.mitm.server.sendPDU.assert_not_called()

    def test_handleCreateResponse_createsNoFile(self, mock_open):
        createRequest = Mock(
            deviceID = 0,
            completionID = 0,
            desiredAccess = (FileAccessMask.GENERIC_READ | FileAccessMask.FILE_READ_DATA),
            createOptions = CreateOption.FILE_NON_DIRECTORY_FILE,
            path = "file",
        )
        createResponse = Mock(deviceID = 0, completionID = 0, fileID = 0)

        with patch("pyrdp.mitm.FileMapping.FileMapping.generate") as generate:
            self.mitm.handleCreateResponse(createRequest, createResponse)
            self.assertEqual(len(self.mitm.openedFiles), 1)
            generate.assert_called_once()
            mock_open.assert_not_called()

    def test_handleReadResponse_createsFile(self, mock_open):
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

        with patch("pyrdp.mitm.FileMapping.FileMapping.generate") as generate:
            self.mitm.handleCreateResponse(request, response)
            self.mitm.handleReadResponse(request, response)
            mock_open.assert_called_once()
            self.mitm.saveMapping.assert_called_once()

            # Make sure it checks the file ID
            request.fileID, response.fileID = 1, 1
            mock_write = Mock()
            list(self.mitm.openedFiles.values())[0].write = mock_write
            self.mitm.handleReadResponse(request, response)
            mock_write.assert_not_called()

    def test_handleCloseResponse_closesFile(self, mock_open):
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

        with patch("pyrdp.mitm.FileMapping.FileMapping.generate") as generate:
            close = Mock()

            self.mitm.handleCreateResponse(request, response)

            mapping = list(self.mitm.openedMappings.values())[0]
            mapping.renameToHash = Mock()
            self.mitm.fileMap[mapping.localPath.name] = Mock()

            file = list(self.mitm.openedFiles.values())[0]
            file.close = close
            file.file = Mock()

            self.mitm.handleCloseResponse(request, response)

            close.assert_called_once()
            mapping.renameToHash.assert_called_once()
            self.mitm.saveMapping.assert_called_once()

    def test_handleCloseResponse_removesDuplicates(self, mock_open):
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
        hash = "hash"

        with patch("pyrdp.mitm.FileMapping.FileMapping.generate") as generate, patch("hashlib.sha1") as sha1:
            sha1.return_value.hexdigest = Mock(return_value = hash)
            self.mitm.handleCreateResponse(request, response)

            list(self.mitm.openedFiles.values())[0].file = Mock()
            mapping = list(self.mitm.openedMappings.values())[0]
            mapping.localPath.unlink = Mock()
            self.mitm.fileMap[mapping.localPath.name] = Mock()
            self.mitm.fileMap["duplicate"] = Mock(hash = hash)

            self.mitm.handleCloseResponse(request, response)
            mapping.localPath.unlink.assert_called_once()
            self.mitm.saveMapping.assert_called_once()


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
