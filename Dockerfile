FROM ubuntu:18.04

# Install Dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        # Required for local pip install
        python3-setuptools \
        # Required to build dbus-python
        build-essential python3-dev \
        libdbus-1-dev \
        libdbus-glib-1-dev \
        libgl1-mesa-glx \
        notify-osd dbus-x11 \
    && rm -rf /var/lib/apt/lists/*

COPY . /pyrdp

RUN cd /pyrdp \
    && pip3 --no-cache-dir install -e . -U

# Create user
RUN useradd --create-home --home-dir /home/pyrdp pyrdp 
USER pyrdp

WORKDIR /home/pyrdp
