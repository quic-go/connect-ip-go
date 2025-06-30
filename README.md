# Proxying IP over HTTP 

[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/connect-ip-go)](https://pkg.go.dev/github.com/quic-go/connect-ip-go)
[![Code Coverage](https://img.shields.io/codecov/c/github/quic-go/connect-ip-go/master.svg?style=flat-square)](https://codecov.io/gh/quic-go/connect-ip-go/)

connect-ip-go is an implementation of the CONNECT-IP protocol [RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484), allowing the proxying of IP packets in HTTP/3.

It is based on [quic-go](https://github.com/quic-go/quic-go), and provides both a client and a proxy implementation.

At this point, it supports the following use cases:
* Remote Access VPN, see [Section 8.1 of RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484#section-8.1)
* Site-to-Site VPN, see [Section 8.2 of RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484#section-8.2)


## Release Policy

connect-ip-go always aims to support the latest two Go releases.

## Contributing

We are always happy to welcome new contributors! If you have any questions, please feel free to reach out by opening an issue or leaving a comment.
