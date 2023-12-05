# Handles compiling and package installation
FROM ubuntu:20.04 AS compile-image

# Install build dependencies
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        # Required for local pip install
        python3-setuptools \
        # Required for venv setup
        python3-venv \
        # Required to build RLE module
        build-essential python3-dev \
        # Required to build PyAV (pyrdp-convert to MP4)
        libavformat-dev libavcodec-dev libavdevice-dev \
        libavutil-dev libswscale-dev libswresample-dev libavfilter-dev

RUN python3 -m venv /opt/venv
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies only (speeds repetitive builds)
COPY requirements.txt /pyrdp/requirements.txt
RUN cd /pyrdp && \
    pip3 install wheel && \
    pip3 --no-cache-dir install --default-timeout=100 -r requirements.txt

# Compile only our C extension and install
# This way changes to source tree will not trigger full images rebuilds
COPY ext/rle.c /pyrdp/ext/rle.c
COPY setup.py /pyrdp/setup.py
COPY pyproject.toml /pyrdp/pyproject.toml
RUN cd /pyrdp \
    && pip3 --no-cache-dir install '.[full]'


# Handles runtime only (minimize size for distribution)
FROM ubuntu:20.04 AS docker-image

# Install runtime dependencies except pre-built venv
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
        # To generate certificates
        openssl \
        # Required for the setup.py install and progressbar (required by pyrdp-convert)
        python3-distutils \
        # GUI and notifications stuff
        libgl1-mesa-glx libxcb-xinerama0 \
        libxcb-icccm4 libxcb-image0 libxcb-util1 libxcb-keysyms1 \
        libxcb-randr0 libxcb-render-util0 \
        libxkbcommon-x11-0 \
        libnotify-bin \
        # Runtime requirement for PyAV (pyrdp-convert to MP4)
        libavcodec58 libavdevice58 \
        && rm -rf /var/lib/apt/lists/*

# Copy preinstalled dependencies from compile image
COPY --from=compile-image /opt/venv /opt/venv

# Create user
RUN useradd --create-home --home-dir /home/pyrdp pyrdp

# Make sure we use the virtualenv
ENV PATH="/opt/venv/bin:$PATH"

# Install python source and package
# NOTE: we are no longer doing this in the compile image to avoid long image rebuilds in development
COPY --from=compile-image /pyrdp /pyrdp
COPY pyrdp/ /pyrdp/pyrdp/
COPY setup.py /pyrdp/setup.py
COPY pyproject.toml /pyrdp/pyproject.toml
RUN cd /pyrdp \
    && python setup.py install

USER pyrdp

# UTF-8 support on the console output (for pyrdp-player)
ENV PYTHONIOENCODING=utf-8
# Make sure we use the virtualenv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /home/pyrdp
