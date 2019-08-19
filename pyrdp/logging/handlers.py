#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging

# Dependency not installed on Windows. Notifications are not supported
try:
    import notify2
except ImportError:
    pass

class NotifyHandler(logging.StreamHandler):
    """
    Logging handler that sends desktop notifications.
    """

    def __init__(self):
        notify2.init("pyrdp-player")
        super(NotifyHandler, self).__init__()

    def emit(self, record):
        """
        Send a notification.
        :param record: the LogRecord object
        """
        notification = notify2.Notification(record.getMessage())
        notification.show()