#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

FROM ubuntu:18.04

RUN apt-get update

# Install Dependencies
RUN apt-get install python3 python3-pip -y
RUN apt-get install notify-osd dbus-x11 python3-pyqt4 libdbus-1-dev libdbus-glib-1-dev -y

COPY . /pyrdp

RUN cd /pyrdp \
    && pip3 install -e .

# Create user
RUN useradd --create-home --home-dir /home/pyrdp pyrdp 
USER pyrdp

WORKDIR /home/pyrdp
