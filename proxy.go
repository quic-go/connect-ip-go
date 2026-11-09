package connectip

import (
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

var contextIDZero = quicvarint.Append([]byte{}, 0)

type Proxy struct{}

// Proxy accepts a request parsed by [ParseProxyRequest] and returns the proxied connection.
//
// On an HTTP/2 server, which needs to run with GODEBUG=http2xconnect=1 to accept the request
// (Extended CONNECT is disabled by default), the HTTP handler must not return
// before the returned Conn is closed: the stream ends with the handler. The ResponseWriter
// must support [http.ResponseController.Flush] and [http.ResponseController.SetWriteDeadline],
// as the one of net/http does: a middleware that wraps it needs an Unwrap method.
func (s *Proxy) Proxy(w http.ResponseWriter, r *ProxyRequest) (*Conn, error) {
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	if r.body != nil {
		return proxyHTTP2(w, r.body)
	}
	w.WriteHeader(http.StatusOK)

	str, err := w.(http3.HTTPStreamer).HTTPStream()
	if err != nil {
		return nil, err
	}
	return newProxiedConn(str, nil), nil
}
