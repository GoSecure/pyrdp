from logging import Filter, LogRecord

from pyrdp.core.Config import Config
from pyrdp.core.logging.ActiveSessions import ActiveSessions


class SensorFilter(Filter):
    """
    Filter that adds the sensor id to the logrecord's arguments.
    """

    def __init__(self):
        super().__init__()

    def filter(self, record: LogRecord) -> bool:
        record.args.update({"sensorId": Config.arguments.sensor_id})
        return True


class ConnectionMetadataFilter(Filter):
    """
    Filter that adds arguments to the record regarding the
    active session (such as source IP and port)
    """

    def __init__(self, sessionId: str):
        self.info = ActiveSessions.get(sessionId)
        super().__init__()

    def filter(self, record: LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = {}
        clientInfo = self.info.tcp.transport.client
        record.args.update({
            "source_ip": clientInfo[0],
            "source_port": clientInfo[1]
        })
        return True
