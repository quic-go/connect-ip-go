FROM ubuntu:24.04

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump iputils-ping iproute2 tcpdump

COPY client /client

ENTRYPOINT ["/client"]
