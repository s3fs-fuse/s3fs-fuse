FROM ubuntu:14.04
MAINTAINER Mathieu Buffenoir <mathieu@buffenoir.tech>

RUN apt-get update -qq
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y git build-essential fuse libfuse-dev libcurl4-openssl-dev libxml2-dev mime-support automake libtool curl tar

COPY . /usr/src/
WORKDIR /usr/src/

RUN ./autogen.sh && ./configure --prefix=/usr && make && make install

ENTRYPOINT ["s3fs"]
CMD ["--help"]
