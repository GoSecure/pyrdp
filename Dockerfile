# Handles compiling and package installation
FROM ubuntu:22.04 AS compile-image

# Install build dependencies
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        # Required to build RLE module
        build-essential python3-dev

RUN python3 -m venv /opt/venv
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"

# Python packaging tooling evolved quickly, we need to get latest, especially on old Pythons
RUN pip --no-cache-dir install -U pip setuptools wheel

# Install dependencies only (speeds repetitive builds)
COPY requirements.txt /pyrdp/requirements.txt
RUN cd /pyrdp && \
    pip --no-cache-dir install --default-timeout=100 -r requirements.txt

# Compile only our C extension and install
# This way changes to source tree will not trigger full images rebuilds
COPY ext/rle.c /pyrdp/ext/
COPY setup.py /pyrdp/
COPY README.md /pyrdp/
COPY pyproject.toml /pyrdp/
COPY pyrdp/ /pyrdp/pyrdp/
RUN cd /pyrdp \
    && pip --no-cache-dir install --no-deps '.[full]'


# Handles runtime only (minimize size for distribution)
FROM ubuntu:22.04 AS runtime-image

# Install runtime dependencies except pre-built venv
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
        # To generate certificates
        openssl \
        # GUI and notifications stuff
        libegl1 libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-keysyms1 \
        libnotify-bin \
        # Runtime requirement for PyAV (pyrdp-convert to MP4)
        libavcodec58 libavdevice58 \
        # minimize image size
        && rm -rf /var/lib/apt/lists/*

# Copy preinstalled dependencies from compile image
COPY --from=compile-image /opt/venv /opt/venv

# Create user
RUN useradd --create-home --home-dir /home/pyrdp pyrdp

# Copy python source
COPY --from=compile-image /pyrdp /pyrdp

USER pyrdp

# UTF-8 support on the console output (for pyrdp-player)
ENV PYTHONIOENCODING=utf-8
# Make sure we use the virtualenv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /home/pyrdp
