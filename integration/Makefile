.PHONY: all client server proxy keygen pingtest

build: keygen proxy server client

keygen:
	openssl genpkey -algorithm Ed25519 -out proxy/key.pem
	openssl req -new -x509 -key proxy/key.pem -out proxy/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"

proxy:
	GOOS=linux go build -o proxy/proxy ./proxy

server:
	GOOS=linux go build -o server/server ./server

client:
	GOOS=linux go build -o client/client ./client

cleanup:
	rm client/client || true
	rm server/server || true
	rm proxy/proxy || true
	rm proxy/key.pem proxy/cert.pem || true

pingtest: build
	TESTCASE=ping docker compose up --build --exit-code-from client
	$(MAKE) cleanup
