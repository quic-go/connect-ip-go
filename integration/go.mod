module github.com/quic-go/connect-ip-go/integration

go 1.26.0

replace github.com/quic-go/connect-ip-go => ..

require (
	// This version is a placeholder; the replacement above always uses the current checkout.
	github.com/quic-go/connect-ip-go v0.0.0
	github.com/quic-go/quic-go v0.62.0
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/stretchr/testify v1.12.1
	github.com/vishvananda/netlink v1.3.0
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/dunglas/httpsfv v1.1.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
