FROM golang:1.24.4

RUN \
    apt-get update \
      && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
         netcat-openbsd \
         python3 \
         python3-pip \
         python3-venv \
      && rm -rf /var/lib/apt/lists/*

# Use a virtualenv to avoid the PEP668 "externally managed environment" error caused by conflicts
# with the system Python installation. golang:1.20.6 uses Debian 12 which now enforces PEP668.
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip3 install --upgrade pip==20.1.1

# Setup work environment
ENV HEARTBEAT_PATH /go/src/github.com/elastic/beats/heartbeat

RUN mkdir -p $HEARTBEAT_PATH/build/coverage
WORKDIR $HEARTBEAT_PATH

# Add healthcheck for docker/healthcheck metricset to check during testing
HEALTHCHECK CMD exit 0
