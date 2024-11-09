FROM ubuntu:24.04

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump iputils-ping iproute2 iptables ethtool tcpdump

COPY proxy /proxy
COPY cert.pem /cert.pem
COPY key.pem /key.pem
COPY run.sh /run.sh

RUN chmod +x /run.sh

EXPOSE 443/udp

ENTRYPOINT ["/run.sh"]
