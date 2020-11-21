FROM cryptogarageinc/elements-testing:v0.18.1.7

ENV PATH /usr/local/bin:$PATH
ENV LANG C.UTF-8

RUN apt update && apt install -y \
    python3 \
    python3-dev \
    python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN bitcoin-cli --version && elements-cli --version
