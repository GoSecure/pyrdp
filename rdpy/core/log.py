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


class SSLSecretFormatter(logging.Formatter):
    """
    Custom formatter used to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super(SSLSecretFormatter, self).__init__("format")

    def format(self, record):
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg),
                                            binascii.hexlify(record.args[0]))




def get_formatter():
    """
    Get the log formatter used for the RDPY library.
    """
    return logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")


def prepare_rdpy_logger():
    """
    Prepare the RDPY logger to be used by the library.
    """
    logger = logging.getLogger("rdpy")
    logger.setLevel(logging.WARNING)
    stream_handler = logging.StreamHandler()
    formatter = get_formatter()
    stream_handler.setFormatter(formatter)
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


prepare_rdpy_logger()
prepare_ssl_session_logger()