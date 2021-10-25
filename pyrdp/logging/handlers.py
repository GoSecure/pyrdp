#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging

# Dependency not installed on Windows. Notifications are not supported
try:
    from pynotifier import Notification
except ImportError:
    pass

class NotifyHandler(logging.StreamHandler):
    """
    Logging handler that sends desktop notifications.
    """

    def __init__(self):
        super(NotifyHandler, self).__init__()

    def emit(self, record):
        """
        Send a notification.
        :param record: the LogRecord object
        """
        try:
            Notification(
                title='PyRDP',
                description=record.getMessage(),
                # duration=5,  # seconds
                urgency='normal'
            ).send()
        except:
            # Either libnotify-bin is not installed or the platform does not support notifications.
            pass