#
# This file is part of the PyRDP project.
# Copyright (C) 2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from configparser import ConfigParser, ExtendedInterpolation

import appdirs
CONFIG_DIR = appdirs.user_config_dir("pyrdp", "pyrdp")


def load(path: str, fallback: ConfigParser = None) -> ConfigParser:
    """
    Retrieve the PyRDP settings from a file

    :param path: The path of the file to load.
    :param fallback: The fallback configuration path.

    :returns: A ConfigParser instance with the loaded settings.
    :throws Exception: When the fallback configuration is missing and no configuration is found.
    """
    config = ConfigParser(interpolation=ExtendedInterpolation())
    config.optionxform = str
    try:
        if len(config.read(path)) > 0:
            return config
    except Exception:
        # Fallback to default settings.
        pass

    if not fallback:
        raise Exception('Invalid configuration with no fallback specified')
    return fallback
