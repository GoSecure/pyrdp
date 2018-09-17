#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import logging
import binascii


def get_formatter():
    """
        :return: The log formatter used for the RDPY library.
    """
    return logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")


def prepare_rdpy_logger():
    """
        Prepare the "rdpy" logger to be used by the library.
    """
    global logger
    logger = logging.getLogger("rdpy")
    logger.setLevel(logging.WARNING)
    stream_handler = logging.StreamHandler()
    formatter = get_formatter()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)


prepare_rdpy_logger()

class SslSecretFormatter(logging.Formatter):
    """
        Custom formatter to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super(SslSecretFormatter, self).__init__("format")

    def format(self, record):
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg),
                                            binascii.hexlify(record.args[0]))


def prepare_ssl_session_logger():
    """
        Prepares the ssl master secret logger. Used to log
        TLS sessions secrets to decrypt traffic latter.
    """

    ssl_logger = logging.getLogger("ssl")
    ssl_logger.setLevel(logging.INFO)
    handler = logging.FileHandler("log/ssl_master_secret.log")
    formatter = SslSecretFormatter()
    handler.setFormatter(formatter)
    ssl_logger.addHandler(handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    ssl_logger.addHandler(stream_handler)


prepare_ssl_session_logger()


def get_logger():
    """
        :return: The logger to use in the library.
    """
    return logger


def get_ssl_logger():
    return logging.getLogger("ssl")


def debug(message):
    logger.debug(message)


def log(message):
    logger.info(message)


def info(message):
    logger.info(message)


def warning(message):
    logger.warning(message)


def error(message):
    logger.error(message)
