package connectip

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
)

func TestClientInvalidTemplate(t *testing.T) {
	_, err := NewRequest(
		t.Context(),
		uritemplate.MustNew("https://example.org/.well-known/masque/ip/{target}/{ipproto}/"),
	)
	require.ErrorContains(t, err, "connect-ip: IP flow forwarding not supported")
}

func TestClientWaitForSettings(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	ln, err := quic.Listen(conn, tlsConf, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		conn.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	defer cconn.CloseWithError(0, "")
	clientConn, err := new(Transport).NewClientConn(cconn)
	require.NoError(t, err)
	req, err := NewRequest(ctx, uritemplate.MustNew("https://example.org/.well-known/masque/ip/"))
	require.NoError(t, err)
	// We're connecting to a QUIC, not an HTTP/3 server.
	// We'll never receive any HTTP/3 settings.
	_, _, err = clientConn.Dial(req)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestClientDatagramCheck(t *testing.T) {
	s := http3.Server{
		TLSConfig:       tlsConf,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		EnableDatagrams: false,
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	go func() { s.Serve(ln) }()
	defer s.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		ln.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	defer cconn.CloseWithError(0, "")

	clientConn, err := new(Transport).NewClientConn(cconn)
	require.NoError(t, err)
	req, err := NewRequest(ctx, uritemplate.MustNew("https://example.org/.well-known/masque/ip/"))
	require.NoError(t, err)
	_, _, err = clientConn.Dial(req)
	require.ErrorContains(t, err, "connect-ip: server didn't enable datagrams")
}

func TestTransportRequiresDatagrams(t *testing.T) {
	req, err := NewRequest(t.Context(), uritemplate.MustNew("https://localhost/connect-ip"))
	require.NoError(t, err)
	_, _, err = (&Transport{QUICConfig: &quic.Config{}}).Dial(req)
	require.ErrorContains(t, err, "QUICConfig needs to enable datagrams")
}

func TestNewClientConnRequiresDatagrams(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	ln, err := quic.Listen(conn, tlsConf, nil)
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	cconn, err := quic.DialAddr(
		ctx,
		conn.LocalAddr().String(),
		&tls.Config{ServerName: "localhost", RootCAs: certPool, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true},
	)
	require.NoError(t, err)
	defer cconn.CloseWithError(0, "")

	_, err = new(Transport).NewClientConn(cconn)
	require.ErrorContains(t, err, "QUIC connection needs datagram support")
}
