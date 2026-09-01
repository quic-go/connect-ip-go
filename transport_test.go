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
