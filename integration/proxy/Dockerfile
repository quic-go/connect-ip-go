FROM ubuntu:24.04

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump iputils-ping iproute2 iptables ethtool tcpdump

COPY proxy cert.pem key.pem run.sh /

RUN chmod +x /run.sh

EXPOSE 443/udp

ENTRYPOINT ["/run.sh"]
