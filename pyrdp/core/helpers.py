#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
File that contains helper methods to use in the library.
"""
import logging
from logging import Logger


class FilePositionGuard:
    """
    Object that can be used in a 'with' statement that will restore a file's pointer to the position it had at
    the start of the with statement. E.g:

    # file position is 200
    with FilePositionGuard(file):
        file.read(10)
        file.tell() # file position is now 210

    file.tell() # file position is now 200 again
    """

    def __init__(self, file):
        self.file = file
        self.startingPosition = None

    def __enter__(self):
        self.startingPosition = self.file.tell()
        return self

    def __exit__(self, exc_type, exception, traceback):
        self.file.seek(self.startingPosition)


def decodeUTF16LE(data: bytes) -> str:
    """
    Decode the provided bytes in UTF-16 in a way that does not crash when invalid input is provided.
    :param data: The data to decode as utf-16.
    :return: The python string
    """
    return data.decode("utf-16le", errors="ignore")


def encodeUTF16LE(string: str) -> bytes:
    """
    Encode the provided string in UTF-16 in a way that does not crash when invalid input is provided.
    :param string: The python string to encode to bytes
    :return: The raw bytes
    """
    return string.encode("utf-16le", errors="ignore")


def getLoggerPassFilters(loggerName: str) -> Logger:
    """
    Returns a logger instance where the filters of all the parent chain are applied to it.
    This is needed since Filters do NOT get inherited from parent logger to child logger.
    See: https://docs.python.org/3/library/logging.html#filter-objects
    """
    logger = logging.getLogger(loggerName)
    subLoggerNames = loggerName.split(".")
    filterList = []
    parentLoggerName = ""
    for subLoggerName in subLoggerNames:
        parentLoggerName += subLoggerName
        parentLogger = logging.getLogger(parentLoggerName)
        filterList += parentLogger.filters
        parentLoggerName += "."
    [logger.addFilter(parentFilter) for parentFilter in filterList]
    return logger
