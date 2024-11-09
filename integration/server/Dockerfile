FROM ubuntu:24.04

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump iputils-ping iproute2 iptables ethtool tcpdump

COPY run.sh cert.pem key.pem server /

RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
