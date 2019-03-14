#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from abc import ABCMeta, abstractmethod

from pyrdp.parser.parser import Parser


class SegmentationParser(Parser, metaclass=ABCMeta):
    @abstractmethod
    def isCompletePDU(self, data: bytes) -> bool:
        """
        Check if a stream of data contains a complete PDU.
        :param data: the data.
        :return: True if the data contains a complete PDU.
        """
        raise NotImplementedError("isCompletePDU must be overridden")

    @abstractmethod
    def getPDULength(self, data: bytes) -> int:
        """
        Get the length of data required for the PDU contained in a stream of data.
        :param data: the data.
        :return: length required.
        """
        raise NotImplementedError("getPDULength must be overridden")