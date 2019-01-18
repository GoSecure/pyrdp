#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

FROM ubuntu:18.04
COPY . /pyrdp
RUN apt-get update \ 
&& apt-get -y upgrade \
#Install Dependencies
&& cd /pyrdp \
&& apt-get install notify-osd -y \
&& apt-get install dbus-x11 -y \
&& apt-get -y install python3 \
&& apt-get -y install python3-pip \
&& pip3 install --upgrade setuptools \
&& pip3 install -U cryptography \
&& apt-get install python3-pyqt4 -y \
&& python3 setup.py install \
&& export PATH=$PATH:/pyrdp/bin \
&& apt-get install sudo 
#Create user
RUN useradd --create-home --home-dir /home/developer developer
USER developer
WORKDIR /home/developer
RUN mkdir /home/developer/log
ENV QT_X11_NO_MITSHM=1

