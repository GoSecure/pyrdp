from logging import Filter, LogRecord

from pyrdp.core.Config import Config


class SensorFilter(Filter):
    """
    Filter that adds the sensor id to the logrecord's arguments.
    """

    def __init__(self):
        super().__init__()

    def filter(self, record: LogRecord):
        record.args.update({"sensorId": Config.arguments.sensor_id})
        return True
