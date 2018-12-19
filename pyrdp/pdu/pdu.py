#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import pprint


class PDU:
    """
    Base class to represent a Protocol Data Unit (PDU).
    If a PDU does not have a payload, simply set it to None.
    """

    def __init__(self, payload=b""):
        """
        :param payload: The PDU's payload data
        :type payload: bytes
        """

        self.payload = payload

    def __repr__(self):
        return pprint.pformat(self.__dict__, width=2000, indent=4, compact=False)
