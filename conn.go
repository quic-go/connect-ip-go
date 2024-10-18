package connectip

import "github.com/quic-go/quic-go/http3"

type Conn struct{}

func newProxiedConn(stream http3.RequestStream) *Conn {
	return &Conn{}
}
