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

ping:
	TESTCASE=ping docker compose --env-file ipv4.env up --exit-code-from client

pingv6:
	TESTCASE=ping docker compose --env-file ipv6.env up --exit-code-from client

http:
	TESTCASE=http docker compose --env-file ipv4.env up --exit-code-from client

httpv6:
	TESTCASE=http docker compose --env-file ipv6.env up --exit-code-from client

http3:
	TESTCASE=http3 docker compose --env-file ipv4.env up --exit-code-from client

http3v6:
	TESTCASE=http3 docker compose --env-file ipv6.env up --exit-code-from client

copylogs:
	mkdir -p $(target)
	docker compose logs > $(target)/docker-compose.log
	docker cp client:/keys.txt $(target)/
	docker cp client:/client.pcap $(target)/
	docker cp server:/server.pcap $(target)/
	docker cp proxy:/proxy_eth0.pcap $(target)/
	docker cp proxy:/proxy_eth1.pcap $(target)/


