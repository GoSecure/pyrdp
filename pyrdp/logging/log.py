#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
import logging.config
from configparser import ConfigParser

from pathlib import Path
from pyrdp.logging.filters import LoggerNameFilter


class LOGGER_NAMES:
    # Root logger
    PYRDP = "pyrdp"
    MITM = f"{PYRDP}.mitm"
    MITM_CONNECTIONS = f"{MITM}.connections"
    PLAYER = f"{PYRDP}.player"
    PLAYER_UI = f"{PLAYER}.ui"

    # Independent logger
    CRAWLER = "crawler"


def getSSLLogger():
    """
    Get the SSL logger.
    """
    return logging.getLogger("ssl")


def info(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).info(*args)


def debug(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).debug(*args)


def warning(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).warning(*args)


def error(*args):
    logging.getLogger(LOGGER_NAMES.PYRDP).error(*args)


def convertConfig(cfg: ConfigParser):
    """
    Transform a config file into a dictionary.

    Keys with the title format `section:subsection:subsection` are
    transformed into nested dictionaries

    # Examples

    ```ini
    [toplevel]
    a = 1
    b = 2

    [toplevel:sublevel]
    c = 3
    d = 4
    ```

    would convert to

    ```python
    'toplevel': {
        'a': 1,
        'b': 2,
        'sublevel': {
            'c': 3,
            'd': 4,
        }
    }
    ````
    """
    def get(d: dict, key: str, create=False) -> dict:
        """Resolve a nested key in a dictionary."""
        nested = key.split(':')
        sub = None
        for n in nested:
            if sub is None:  # Top Level
                if n not in d:
                    if not create:
                        return None
                    d[n] = {}
                sub = d[n]
            else:
                if n not in sub:
                    if not create:
                        return None
                    sub[n] = {}
                sub = sub[n]
        return sub

    out = {}
    for s in cfg.sections():
        sec = get(out, s, create=True)
        for (k, v) in cfg.items(s):
            sec[k] = v
    return out


def configure(config: ConfigParser) -> bool:
    """Configure logging based on settings from disk."""
    try:
        cfg = convertConfig(config)
        logs = cfg['logs']
        logs['version'] = int(logs['version'])  # Needs to be integer.

        for (k, v) in logs['loggers'].items():
            v['handlers'] = [x.strip() for x in v['handlers'].split(',')]

        # Ensure log directory exists.
        logDir = Path(cfg['vars']['output_dir']) / cfg['vars']['log_dir']
        logDir.mkdir(exist_ok = True)

        logging.config.dictConfig(cfg['logs'])

        # Enable the user configured filter.
        if 'filter' in logs:
            root = logging.getLogger(LOGGER_NAMES.PYRDP)
            for h in root.handlers:
                # Use type() because we want specific type, not a subclass.
                if type(h) == logging.StreamHandler:
                    h.filters.clear()
                    h.addFilter(LoggerNameFilter(logs['filter']))
        return True
    except Exception as e:
        logging.warning('Error Parsing PyRDP Configuraton - %s', e)
        return False
