import binascii
import logging


class SSLSecretFormatter(logging.Formatter):
    """
    Custom formatter used to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super(SSLSecretFormatter, self).__init__("format")

    def format(self, record):
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg).decode(),
                                            binascii.hexlify(record.args[0]).decode())


def get_formatter():
    """
    Get the log formatter used for the RDPY library.
    """
    return logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")


def prepare_rdpy_logger(logLevel = logging.INFO):
    """
    Prepare the RDPY logger to be used by the library.
    """
    logger = logging.getLogger("rdpy")
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
    return logging.getLogger("rdpy")


def get_ssl_logger():
    """
    Get the SSL logger.
    """
    return logging.getLogger("ssl")


def info(message):
    get_logger().info(message)


def debug(message):
    get_logger().debug(message)


def warning(message):
    get_logger().warning(message)


def error(message):
    get_logger().error(message)