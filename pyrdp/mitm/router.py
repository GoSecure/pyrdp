from pyrdp.logging import log
from pyrdp.mcs import MCSServerRouter
from pyrdp.pdu import MCSSendDataRequestPDU


class MITMServerRouter(MCSServerRouter):
    """
    Like MCSServerRouter, but change the user ID in case of invalid user ID.
    """

    def onInvalidMCSUser(self, pdu: MCSSendDataRequestPDU):
        goodUserId = next(iter(self.users))
        log.warning(f"Invalid MCS userID received: {pdu.initiator} changing to {goodUserId}.")
        pdu.initiator = goodUserId
        self.onSendDataRequest(pdu)
