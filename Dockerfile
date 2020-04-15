# Handles compiling and package installation
FROM ubuntu:18.04 AS compile-image
# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        # Required for local pip install
        python3-setuptools \
        # Required for venv setup
        python3-venv \
        # Required to build RLE module and dbus-python (GUI)
        build-essential python3-dev \
        libdbus-1-dev \
        libdbus-glib-1-dev

RUN python3 -m venv /opt/venv
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"

# Copy only what is required for the install
COPY setup.py /pyrdp/setup.py
COPY bin/ /pyrdp/bin/
COPY ext/rle.c /pyrdp/ext/rle.c
COPY pyrdp/ /pyrdp/pyrdp/
# Install in the virtualenv
RUN cd /pyrdp \
    && pip3 --no-cache-dir install .[full] -U


# Handles runtime only (minimize size for distribution)
FROM ubuntu:18.04 AS docker-image

# Install runtime dependencies except pre-built venv
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
        # GUI and notifications stuff
        libgl1-mesa-glx \
        notify-osd dbus-x11 libxkbcommon-x11-0 \
        && rm -rf /var/lib/apt/lists/*

# Copy preinstalled dependencies from compile image
COPY --from=compile-image /opt/venv /opt/venv

# Create user
RUN useradd --create-home --home-dir /home/pyrdp pyrdp
USER pyrdp

# UTF-8 support on the console output (for pyrdp-player)
ENV PYTHONIOENCODING=utf-8
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /home/pyrdp
