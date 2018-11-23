import pprint


class PDU:
    """
    Base class to represent a Protocol Data Unit (PDU).
    If a PDU does not have a payload, simply set it to None.
    """

    def __init__(self, payload=None):
        """
        :param payload: The PDU's payload data
        :type payload: bytes
        """

        self.payload = payload

    def __repr__(self):
        return pprint.pformat(vars(self))
