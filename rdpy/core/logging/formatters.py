"""
Contains custom logging handlers for the library.
"""
import binascii
import logging


class SSLSecretFormatter(logging.Formatter):
    """
    Custom formatter used to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super(SSLSecretFormatter, self).__init__("format")

    def format(self, record: logging.LogRecord):
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg).decode(),
                                            binascii.hexlify(record.args[0]).decode())
