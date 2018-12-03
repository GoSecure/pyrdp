"""
Contains custom logging handlers for the library.
"""
import binascii
import json
import logging


class JSONFormatter(logging.Formatter):
    """
    Formatter that returns a single JSON line of the provided data.
    """

    def __init__(self):
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        data = {
            "message": record.msg,
            "loggerName": record.name,
            "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:S.f%z"),
            "level": record.levelname,
        }
        data.update(record.args)
        return json.dumps(data)


class SSLSecretFormatter(logging.Formatter):
    """
    Custom formatter used to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super(SSLSecretFormatter, self).__init__("format")

    def format(self, record: logging.LogRecord):
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg).decode(),
                                            binascii.hexlify(record.args[0]).decode())
