#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Contains custom logging handlers for the library.
"""

import binascii
import json
import logging
from datetime import datetime


class VariableFormatter(logging.Formatter):
    """
    Formatter class that provides custom format variables with default values.
    """

    def __init__(self, fmt: str = None, datefmt: str = None, style: str = "%", defaultVariables: dict = None):
        super().__init__(fmt = fmt, datefmt = datefmt, style = style)
        self.defaultVariables = defaultVariables if defaultVariables is not None else {}

    def format(self, record: logging.LogRecord) -> str:
        for variable, value in self.defaultVariables.items():
            if not hasattr(record, variable):
                setattr(record, variable, value)

        return super().format(record)


class JSONFormatter(logging.Formatter):
    """
    Formatter that returns a single JSON line of the provided data.
    Example usage: logger.info("MITM Server listening on port %(port)d", {"port": listenPort})
    Will output: {"message": "MITM Server listening on port %(port)d", "loggerName": "mitm", "timestamp": "2018-12-03T10:51:S.f-0500", "level": "INFO", "port": 3388}
    """

    def __init__(self, baseDict: dict = None):
        """
        :param baseDict: dictionary with base values that should be in every log message.
        """
        super().__init__()
        self.baseDict = baseDict if baseDict is not None else {}

    def format(self, record: logging.LogRecord) -> str:
        data = self.baseDict.copy()

        data.update({
            "message": record.msg,
            "loggerName": record.name,
            "timestamp": datetime.strftime(datetime.utcfromtimestamp(record.created), "%Y-%m-%dT%H:%M:%S.%f"),
            "level": record.levelname,
        })

        if hasattr(record, "sessionID"):
            data.update({
                "sessionID": record.sessionID
            })

        if hasattr(record, "clientIp"):
            data.update({
                "clientIp": record.clientIp
            })

        if isinstance(record.args, dict):
            data.update(record.args)

        return json.dumps(data, ensure_ascii=False, default=lambda item: item.__repr__())


class SSLSecretFormatter(logging.Formatter):
    """
    Custom formatter used to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg).decode(),
                                            binascii.hexlify(record.args[0]).decode())


class NTLMSSPHashFormatter(logging.Formatter):
    """
    Custom formatter used to log NTLMSSP hashes.
    """

    @staticmethod
    def formatNTLMSSPHash(user: str, domain: str, serverChallenge: bytes, proof: bytes, response: bytes) -> str:
        return f"{user}::{domain}:{serverChallenge.hex()}:{proof.hex()}:{response.hex()}"

    def format(self, record: logging.LogRecord) -> str:
        user = record.msg
        domain, serverChallenge, proof, response = record.args[0 : 4]
        return NTLMSSPHashFormatter.formatNTLMSSPHash(user, domain, serverChallenge, proof, response)
