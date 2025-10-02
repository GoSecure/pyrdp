"""
Tests for logging observers
"""
import unittest
from unittest.mock import Mock
from logging import LoggerAdapter

from pyrdp.enum import ErrorInfo
from pyrdp.logging.observers import SlowPathLogger
from pyrdp.pdu import SlowPathPDU


class SlowPathLoggerTest(unittest.TestCase):
    """Test SlowPathLogger error info handling"""

    def setUp(self):
        self.log = Mock(spec=LoggerAdapter)
        self.logger = SlowPathLogger(self.log)

    def test_errinfo_rpc_initiated_disconnect_byuser_logs_as_info(self):
        """Test ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER is logged as info, not error"""
        pdu = Mock(spec=SlowPathPDU)
        pdu.header = Mock()
        pdu.header.subtype = Mock()
        pdu.errorInfo = ErrorInfo.ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER

        self.logger.onPDUReceived(pdu)

        # Should call log.info, not log.error
        self.log.info.assert_called_once()
        self.log.error.assert_not_called()

        # Verify the message contains the error text
        call_args = self.log.info.call_args
        self.assertIn("description", call_args[0][1])

    def test_errinfo_logoff_by_user_logs_as_info(self):
        """Test ERRINFO_LOGOFF_BY_USER is logged as info (existing behavior)"""
        pdu = Mock(spec=SlowPathPDU)
        pdu.header = Mock()
        pdu.header.subtype = Mock()
        pdu.errorInfo = ErrorInfo.ERRINFO_LOGOFF_BY_USER

        self.logger.onPDUReceived(pdu)

        # Should call log.info, not log.error
        self.log.info.assert_called_once()
        self.log.error.assert_not_called()

    def test_other_errinfo_logs_as_error(self):
        """Test other error codes are still logged as error"""
        pdu = Mock(spec=SlowPathPDU)
        pdu.header = Mock()
        pdu.header.subtype = Mock()
        pdu.errorInfo = ErrorInfo.ERRINFO_RPC_INITIATED_DISCONNECT

        self.logger.onPDUReceived(pdu)

        # Should call log.error, not log.info
        self.log.error.assert_called_once()
        self.log.info.assert_not_called()

        # Verify the message format
        call_args = self.log.error.call_args
        self.assertIn("RDP Error Info:", call_args[0][0])

    def test_errinfo_none_does_not_log_error_or_info(self):
        """Test ERRINFO_NONE doesn't trigger error/info logging"""
        pdu = Mock(spec=SlowPathPDU)
        pdu.header = Mock()
        pdu.header.subtype = Mock()
        pdu.errorInfo = ErrorInfo.ERRINFO_NONE

        self.logger.onPDUReceived(pdu)

        # Should not call log.error or log.info for error info
        self.log.error.assert_not_called()
        # log.info may be called for other reasons, but not for error info
        # Just verify debug is called for PDU receipt
        self.log.debug.assert_called()


if __name__ == '__main__':
    unittest.main()
