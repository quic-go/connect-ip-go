package connectip

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// defaultInitialPacketSize allows tunneling QUIC connections, which require an MTU of at least 1200 bytes.
const defaultInitialPacketSize = 1350

// A Transport establishes proxied connections to multiple proxy servers.
type Transport struct {
	// TLSClientConfig is the TLS client config used when dialing the QUIC connection to the proxy.
	// It must set the "h3" ALPN.
	TLSClientConfig *tls.Config

	// QUICConfig is the QUIC config used when dialing the QUIC connection.
	QUICConfig *quic.Config

	// DialAddr dials the QUIC connection to the proxy.
	// If unset, quic.DialAddr is used.
	DialAddr func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error)
}

// Dial opens a QUIC connection to the proxy and then dials a proxied connection.
// Closing the returned Conn also closes the QUIC connection to the proxy.
// To establish multiple proxied connections over one proxy connection, use NewClientConn.
func (t *Transport) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil || httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request URL needs a host")
	}

	quicConf := t.QUICConfig
	if quicConf == nil {
		quicConf = &quic.Config{EnableDatagrams: true, InitialPacketSize: defaultInitialPacketSize}
	}
	if !quicConf.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: QUICConfig needs to enable datagrams")
	}
	tlsConf := t.TLSClientConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	}
	dial := t.DialAddr
	if dial == nil {
		dial = quic.DialAddr
	}
	conn, err := dial(httpReq.Context(), httpReq.URL.Host, tlsConf, quicConf)
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: dialing QUIC connection failed: %w", err)
	}
	c, err := t.NewClientConn(conn)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, err
	}
	pconn, rsp, err := c.dial(req, func() error { return conn.CloseWithError(0, "") })
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, rsp, err
	}
	return pconn, rsp, nil
}

// NewClientConn creates a client connection for an already established QUIC connection.
// It returns an error if the QUIC connection didn't negotiate datagram support.
// The caller owns the QUIC connection and closes it when done.
func (t *Transport) NewClientConn(conn *quic.Conn) (*ClientConn, error) {
	datagrams := conn.ConnectionState().SupportsDatagrams
	if !datagrams.Local || !datagrams.Remote {
		return nil, errors.New("connect-ip: QUIC connection needs datagram support")
	}
	tr := &http3.Transport{EnableDatagrams: true}
	return &ClientConn{clientConn: tr.NewClientConn(conn)}, nil
}
