.PHONY: all build endpoints docker-build proxy pingtest httptest http3test

build: proxy endpoints docker-build cleanup

proxy:
	GOOS=linux go build $(if $(RACE),-race) -o proxy/proxy ./proxy

endpoints:
	openssl req -new -x509 -newkey Ed25519 -keyout server/key.pem -out server/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=server" -nodes
	GOOS=linux go build $(if $(RACE),-race) -o server/server ./server
	GOOS=linux go build $(if $(RACE),-race) -o client/client ./client

docker-build:
	openssl req -new -x509 -newkey Ed25519 -keyout proxy/key.pem -out proxy/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=proxy" -nodes
	TESTCASE=build docker compose build

cleanup:
	rm client/client || true
	rm server/server || true
	rm proxy/proxy || true
	rm server/key.pem server/cert.pem || true
	rm proxy/key.pem proxy/cert.pem || true

clean-containers:
	docker compose rm -f client proxy server

ping: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=ping docker compose --env-file ipv4.env up --exit-code-from client

pingv6: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=ping docker compose --env-file ipv6.env up --exit-code-from client

http: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=http docker compose --env-file ipv4.env up --exit-code-from client

httpv6: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=http docker compose --env-file ipv6.env up --exit-code-from client

http3: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=http3 docker compose --env-file ipv4.env up --exit-code-from client

http3v6: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=http3 docker compose --env-file ipv6.env up --exit-code-from client

filtertcp: clean-containers
	FILTER_IP_PROTOCOL=6 TESTCASE=filtertcp docker compose --env-file ipv4.env up --exit-code-from client

filtertcpv6: clean-containers
	FILTER_IP_PROTOCOL=6 TESTCASE=filtertcp docker compose --env-file ipv6.env up --exit-code-from client

filetransfer: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=filetransfer docker compose --env-file ipv4.env up --exit-code-from client

filetransferv6: clean-containers
	FILTER_IP_PROTOCOL=0 TESTCASE=filetransfer docker compose --env-file ipv6.env up --exit-code-from client

copylogs:
	if [ -z "$(target)" ]; then echo "target directory not specified"; exit 1; fi
	rm -rf $(target)
	mkdir -p $(target)
	docker compose logs > $(target)/docker-compose.log
	docker cp client:/keys.txt $(target)/
	docker cp client:/client.pcap $(target)/
	docker cp server:/server.pcap $(target)/
	docker cp proxy:/proxy_eth0.pcap $(target)/
	docker cp proxy:/proxy_eth1.pcap $(target)/

