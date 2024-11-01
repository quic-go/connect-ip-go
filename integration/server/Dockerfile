FROM ubuntu:24.04

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump iputils-ping iproute2 iptables

COPY run.sh /run.sh
COPY server /server

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
