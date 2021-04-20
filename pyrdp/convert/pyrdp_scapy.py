#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

# No choice but to import * here for load_layer to work properly.
from scapy.all import *  # noqa

load_layer("tls")  # noqa
