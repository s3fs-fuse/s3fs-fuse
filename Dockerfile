# Reference: https://github.com/s3fs-fuse/s3fs-fuse/wiki/Installation-Notes

FROM ubuntu:18.04 AS build

ARG SCRIPT_SOURCE_DIR=dockerfile_scripts
ARG SCRIPT_DEST_DIR=/usr/local/bin

# Install general build tools

RUN apt-get update

RUN apt-get install -y \
  build-essential \
  fakeroot \
  dpkg-dev \
  devscripts \
  git \
  curl \
;

RUN apt-get install -y s3fs

RUN apt-get install -y \
    build-essential \
    git \
    libfuse-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    mime-support \
    automake \
    libtool \
    pkg-config \
    libssl-dev \
  ;

RUN mkdir /usr/src/build
COPY . /usr/src/build/s3fs-fuse
WORKDIR /usr/src/build/s3fs-fuse
RUN ./autogen.sh
RUN ./configure
RUN make
RUN make install