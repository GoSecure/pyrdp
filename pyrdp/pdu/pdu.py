#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#


class PDU:
    """
    Base class to represent a Protocol Data Unit (PDU).
    If a PDU does not have a payload, simply set it to None.
    """
    REPR_PAYLOAD_CUTOFF_LENGTH = 200

    def __init__(self, payload=b""):
        """
        :param payload: The PDU's payload data
        :type payload: bytes
        """
        self.payload = payload

    def __repr__(self):
        properties = dict(self.__dict__)

        if len(self.payload) > PDU.REPR_PAYLOAD_CUTOFF_LENGTH:
            properties["payload"] = properties["payload"][: PDU.REPR_PAYLOAD_CUTOFF_LENGTH] + b"<LONG PAYLOAD>"

        representation = self.__class__.__name__ + str(properties)
        return representation