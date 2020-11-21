FROM python:3.9.0-slim-buster as cfdPythonBuilder

RUN apt-get update && apt-get install -y tzdata
ENV TZ=Asia/Tokyo

RUN apt-get install -y \
    gpg \
    wget \
    build-essential \
    git \
  && rm -rf /var/lib/apt/lists/*

ENV GPG_KEY_SERVER hkp://keyserver.ubuntu.com:80

ENV CMAKE_VERSION 3.17.2
ENV CMAKE_TARBALL cmake-${CMAKE_VERSION}-Linux-x86_64.tar.gz
ENV CMAKE_URL_BASE https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}
ENV CMAKE_PGP_KEY C6C265324BBEBDC350B513D02D2CEF1034921684
RUN wget -qO ${CMAKE_TARBALL} ${CMAKE_URL_BASE}/${CMAKE_TARBALL} \
  && gpg --keyserver ${GPG_KEY_SERVER} --recv-keys ${CMAKE_PGP_KEY} \
  && wget -qO cmake-SHA-256.txt ${CMAKE_URL_BASE}/cmake-${CMAKE_VERSION}-SHA-256.txt \
  && wget -qO cmake-SHA-256.txt.asc ${CMAKE_URL_BASE}/cmake-${CMAKE_VERSION}-SHA-256.txt.asc \
  && gpg --verify cmake-SHA-256.txt.asc \
  && sha256sum --ignore-missing --check cmake-SHA-256.txt \
  && tar -xzvf ${CMAKE_TARBALL} --directory=/opt/ \
  && ln -sfn /opt/cmake-${CMAKE_VERSION}-Linux-x86_64/bin/* /usr/bin \
  && rm -f ${CMAKE_TARBALL} cmake-SHA-256.txt cmake-SHA-256.txt.asc

RUN pip3 install wheel

WORKDIR /root

RUN python3 --version && cmake --version && env

ENTRYPOINT ["/bin/bash", "-l", "-c"]