#
# This file is part of the PyRDP project.
# Copyright (C) 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

# Disable line-too-long lints.
# flake8: noqa

from enum import IntEnum


class NTSTATUS(IntEnum):
    """
    [MS-ERREF]: Windows Error Codes
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/87fba13e-bf06-450e-83b1-9241dc81e781
    """
    STATUS_SUCCESS = 0x00000000
    STATUS_NO_MORE_FILES = 0x80000006
    STATUS_NO_SUCH_FILE = 0xC000000F