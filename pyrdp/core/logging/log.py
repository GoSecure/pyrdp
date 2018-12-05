import logging
import os

from pyrdp.core.logging.formatters import SSLSecretFormatter


class LOGGER_NAMES:
    PYRDP = "pyrdp"
    PYRDP_EXCEPTIONS = "pyrdp.exceptions"
    MITM = "mitm"
    MITM_CONNECTIONS = "mitm.connections"
    MITM_CLIENT = "mitm.connections.client"
    MITM_SERVER = "mitm.connections.server"
    MITM_CLIPBOARD_CLIENT = "mitm.clipboard.client"
    MITM_CLIPBOARD_SERVER = "mitm.clipboard.server"
    MITM_DEVICE_CLIENT = "mitm.deviceRedirection.client"
    MITM_DEVICE_SERVER = "mitm.deviceRedirection.server"


def get_formatter():
    """
    Get the log formatter used for the PyRDP library.
    """
    return logging.Formatter("[{asctime}] - {name:<32} - {levelname:<8} - {message}", style="{")


def prepare_pyrdp_logger(logLevel=logging.INFO):
    """
    Prepare the PyRDP logger to be used by the library.
    """
    logger = logging.getLogger(LOGGER_NAMES.PYRDP)
    logger.setLevel(logLevel)

    stream_handler = logging.StreamHandler()

    formatter = get_formatter()

    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logLevel)

    logger.addHandler(stream_handler)


def prepare_ssl_session_logger():
    """
    Prepares the SSL master secret logger. Used to log TLS session secrets to decrypt traffic later.
    """
    ssl_logger = logging.getLogger("ssl")
    ssl_logger.setLevel(logging.INFO)
    os.makedirs("log", exist_ok=True)
    handler = logging.FileHandler("log/ssl_master_secret.log")
    formatter = SSLSecretFormatter()
    handler.setFormatter(formatter)
    ssl_logger.addHandler(handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    ssl_logger.addHandler(stream_handler)


def get_logger():
    """
    Get the main logger.
    """
    return logging.getLogger(LOGGER_NAMES.PYRDP)


def get_ssl_logger():
    """
    Get the SSL logger.
    """
    return logging.getLogger("ssl")


def info(message, *args):
    get_logger().info(message, *args)


def debug(message, *args):
    get_logger().debug(message, *args)


def warning(message, *args):
    get_logger().warning(message, *args)


def error(message, *args):
    get_logger().error(message, *args)
