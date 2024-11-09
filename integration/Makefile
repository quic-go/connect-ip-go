.PHONY: all build client docker-build server proxy pingtest httptest

build: proxy server client docker-build cleanup

proxy:
	GOOS=linux go build -o proxy/proxy ./proxy

server:
	GOOS=linux go build -o server/server ./server

client:
	GOOS=linux go build -o client/client ./client

docker-build:
	openssl genpkey -algorithm Ed25519 -out proxy/key.pem
	openssl req -new -x509 -key proxy/key.pem -out proxy/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
	docker compose build

cleanup:
	rm client/client || true
	rm server/server || true
	rm proxy/proxy || true
	rm proxy/key.pem proxy/cert.pem || true

pingtest:
	TESTCASE=ping docker compose up --exit-code-from client

httptest:
	TESTCASE=http docker compose up --exit-code-from client

copylogs:
	mkdir -p $(target)
	docker compose logs > $(target)/docker-compose.log
	docker cp client:/keys.txt $(target)/
	docker cp client:/client.pcap $(target)/
	docker cp server:/server.pcap $(target)/
	docker cp proxy:/proxy_eth0.pcap $(target)/
	docker cp proxy:/proxy_eth1.pcap $(target)/
