from pyrdp.mcs import MCSServerRouter
from pyrdp.pdu import MCSSendDataRequestPDU


class MITMServerRouter(MCSServerRouter):
    """
    Like MCSServerRouter, but change the user ID in case of invalid user ID.
    """

    def onInvalidMCSUser(self, pdu: MCSSendDataRequestPDU):
        pdu.initiator = next(iter(self.users))
        self.onSendDataRequest(pdu)