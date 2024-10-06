package connectip

import (
	"net"
	"net/http"
	"sync/atomic"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Proxy struct {
	closed atomic.Bool
}

func (s *Proxy) Proxy(w http.ResponseWriter, _ *Request) (*Conn, error) {
	if s.closed.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil, net.ErrClosed
	}
	w.Header().Set(capsuleHeader, capsuleProtocolHeaderValue)
	w.WriteHeader(http.StatusOK)

	str := w.(http3.HTTPStreamer).HTTPStream()
	return newProxiedConn(str), nil
}
