
#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

FROM ubuntu:18.04
COPY . /pyRDPcontainer
WORKDIR /pyRDPcontainer
RUN apt-get update \
&& apt-get -y upgrade \
&& apt-get -y install python3 \
&& apt-get -y install python3-pip \
&& pip3 install --upgrade setuptools \
&& pip3 install -U cryptography \
&& apt-get install python3-pyqt4 -y \
&& python3 setup.py install
WORKDIR /pyRDPcontainer/bin

  



