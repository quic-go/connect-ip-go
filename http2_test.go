package connectip

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/ipv4"
)

// TestMain enables Extended CONNECT on the HTTP/2 server of net/http.
// net/http reads GODEBUG in an init function, so the tests need to run in a new process.
func TestMain(m *testing.M) {
	const debug = "http2xconnect=1"
	if strings.Contains(os.Getenv("GODEBUG"), debug) {
		os.Exit(m.Run())
	}
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "GODEBUG="+strings.TrimPrefix(os.Getenv("GODEBUG")+","+debug, ","))
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	http2ClientAddr = netip.MustParseAddr("10.0.0.2")
	http2ProxyAddr  = netip.MustParseAddr("10.1.0.1")
)

// startHTTP2Server starts a net/http server, restricted to HTTP/2, and returns its address.
func startHTTP2Server(t *testing.T, handler http.HandlerFunc, configure func(*http.Server)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	conf := tlsConf.Clone()
	conf.NextProtos = []string{http2.NextProtoTLS}
	s := &http.Server{Handler: handler, TLSConfig: conf, Protocols: protocols}
	if configure != nil {
		configure(s)
	}
	go func() { s.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { s.Close() })
	return ln.Addr().String()
}

func dialHTTP2(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: "localhost",
		RootCAs:    certPool,
		NextProtos: []string{http2.NextProtoTLS},
	})
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.Equal(t, http2.NextProtoTLS, conn.ConnectionState().NegotiatedProtocol)
	return conn
}

// servingProxy returns a handler that holds a session for as long as the Conn is open,
// as HTTP/2 requires, after sending it to conns.
func servingProxy(t *testing.T, template func() *uritemplate.Template, conns chan<- *Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := ParseProxyRequest(r, template())
		if err != nil {
			t.Errorf("ParseProxyRequest: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, err := (&Proxy{}).Proxy(w, req)
		if err != nil {
			t.Errorf("Proxy: %v", err)
			return
		}
		defer conn.Close()
		conns <- conn
		<-conn.ctx.Done()
	}
}

// setupHTTP2Conns establishes a session with an address and a route, through a real net/http server.
func setupHTTP2Conns(t *testing.T, conf *HTTP2Config, configure func(*http.Server)) (client, proxy *Conn, clientConn *HTTP2ClientConn) {
	t.Helper()
	conns := make(chan *Conn, 1)
	var template *uritemplate.Template
	addr := startHTTP2Server(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		servingProxy(t, func() *uritemplate.Template { return template }, conns)(w, r)
	}, configure)
	template = uritemplate.MustNew("https://" + addr + "/connect-ip?epoch=1")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	clientConn = NewHTTP2ClientConn(dialHTTP2(t, addr), conf)
	t.Cleanup(func() { clientConn.Close() })
	req, err := NewRequest(ctx, template)
	require.NoError(t, err)
	req.Header().Set("Authorization", "Bearer token")
	client, rsp, err := clientConn.Dial(req)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	require.Equal(t, capsuleProtocolHeaderValue, rsp.Header.Get("Capsule-Protocol"))

	select {
	case proxy = <-conns:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the session on the proxy")
	}
	t.Cleanup(func() { proxy.Close() })

	require.NoError(t, proxy.AssignAddresses([]netip.Prefix{netip.PrefixFrom(http2ClientAddr, 32)}))
	require.NoError(t, proxy.AdvertiseRoute([]IPRoute{{StartIP: http2ProxyAddr, EndIP: http2ProxyAddr}}))
	assigned, err := client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Len(t, assigned, 1)
	require.Equal(t, http2ClientAddr, assigned[0].IPPrefix.Addr())
	routes, err := client.Routes(ctx)
	require.NoError(t, err)
	require.Len(t, routes, 1)
	return client, proxy, clientConn
}

func http2TestPacket(t *testing.T, src, dst netip.Addr, payload []byte) []byte {
	t.Helper()
	hdr, err := (&ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TTL:      64,
		Protocol: 253,
		Src:      src.AsSlice(),
		Dst:      dst.AsSlice(),
	}).Marshal()
	require.NoError(t, err)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(hdr)+len(payload)))
	binary.BigEndian.PutUint16(hdr[10:12], calculateIPv4Checksum(hdr))
	return append(hdr, payload...)
}

func requireClosed(t *testing.T, conn *Conn) {
	t.Helper()
	errChan := make(chan error, 1)
	go func() {
		for {
			if _, err := conn.ReadPacket(make([]byte, 1500)); err != nil {
				errChan <- err
				return
			}
		}
	}()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, net.ErrClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPacket didn't return")
	}
}

func TestHTTP2Session(t *testing.T) {
	client, proxy, _ := setupHTTP2Conns(t, nil, nil)

	_, err := client.WritePacket(http2TestPacket(t, http2ClientAddr, http2ProxyAddr, []byte("from the client")))
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, err := proxy.ReadPacket(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("from the client"), buf[ipv4.HeaderLen:n])

	_, err = proxy.WritePacket(http2TestPacket(t, http2ProxyAddr, http2ClientAddr, []byte("from the proxy")))
	require.NoError(t, err)
	n, err = client.ReadPacket(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("from the proxy"), buf[ipv4.HeaderLen:n])
}

func TestHTTP2FullSizePacket(t *testing.T) {
	// A packet that wouldn't fit into a QUIC datagram, and that's spread over several DATA frames.
	client, proxy, _ := setupHTTP2Conns(t, nil, nil)
	payload := bytes.Repeat([]byte("x"), 65535-ipv4.HeaderLen)
	_, err := client.WritePacket(http2TestPacket(t, http2ClientAddr, http2ProxyAddr, payload))
	require.NoError(t, err)
	buf := make([]byte, 65535)
	n, err := proxy.ReadPacket(buf)
	require.NoError(t, err)
	require.Equal(t, 65535, n)
	require.Equal(t, payload, buf[ipv4.HeaderLen:n])
}

func TestHTTP2CloseFromClient(t *testing.T) {
	client, proxy, _ := setupHTTP2Conns(t, nil, nil)
	require.NoError(t, client.Close())
	requireClosed(t, proxy)
	requireClosed(t, client)
}

func TestHTTP2CloseFromProxy(t *testing.T) {
	client, proxy, _ := setupHTTP2Conns(t, nil, nil)
	require.NoError(t, proxy.Close())
	requireClosed(t, client)
	_, err := proxy.WritePacket(http2TestPacket(t, http2ProxyAddr, http2ClientAddr, nil))
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestHTTP2ClientConnClose(t *testing.T) {
	client, proxy, clientConn := setupHTTP2Conns(t, nil, nil)
	require.NoError(t, clientConn.Close())
	requireClosed(t, client)
	requireClosed(t, proxy)
}

func TestHTTP2Refused(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			addr := startHTTP2Server(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "refused", status)
			}, nil)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, err := NewRequest(ctx, uritemplate.MustNew("https://"+addr+"/connect-ip"))
			require.NoError(t, err)
			conn, rsp, err := NewHTTP2ClientConn(dialHTTP2(t, addr), nil).Dial(req)
			require.ErrorContains(t, err, fmt.Sprintf("server responded with %d", status))
			require.Nil(t, conn)
			require.Equal(t, status, rsp.StatusCode)
			require.Equal(t, "HTTP/2.0", rsp.Proto)
		})
	}
}

func TestHTTP2Ping(t *testing.T) {
	_, _, clientConn := setupHTTP2Conns(t, nil, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, clientConn.Ping(ctx))

	require.NoError(t, clientConn.Close())
	require.ErrorIs(t, clientConn.Ping(ctx), net.ErrClosed)
}

func TestHTTP2OutlivesServerTimeouts(t *testing.T) {
	// These are the deadlines of http.Server.ReadTimeout and WriteTimeout, without
	// their effect on the TLS handshake, which would make this test depend on the machine.
	const timeout = 50 * time.Millisecond
	client, proxy, _ := setupHTTP2Conns(t, nil, func(s *http.Server) {
		handler := s.Handler
		s.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			require.NoError(t, rc.SetReadDeadline(time.Now().Add(timeout)))
			require.NoError(t, rc.SetWriteDeadline(time.Now().Add(timeout)))
			handler.ServeHTTP(w, r)
		})
	})
	time.Sleep(3 * timeout)
	_, err := client.WritePacket(http2TestPacket(t, http2ClientAddr, http2ProxyAddr, nil))
	require.NoError(t, err)
	_, err = proxy.WritePacket(http2TestPacket(t, http2ProxyAddr, http2ClientAddr, nil))
	require.NoError(t, err)
	for _, conn := range []*Conn{client, proxy} {
		_, err := conn.ReadPacket(make([]byte, 1500))
		require.NoError(t, err)
	}
}

// TestHTTP2Saturated runs a stream of numbered packets in both directions, more
// than the flow control windows allow, while the capsules of the routes go through.
// Packets can get lost, but never reordered or torn, and the session has to survive.
func TestHTTP2Saturated(t *testing.T) {
	const (
		packets    = 4000
		payloadLen = 1400
		routes     = maxRoutesPerCapsule
	)
	client, proxy, clientConn := setupHTTP2Conns(t, &HTTP2Config{ReceiveWindow: http2InitialWindow}, nil)

	send := func(conn *Conn, src, dst netip.Addr) error {
		for i := range packets {
			payload := make([]byte, payloadLen)
			binary.BigEndian.PutUint64(payload, uint64(i))
			for j := 8; j < len(payload); j++ {
				payload[j] = byte(i)
			}
			if _, err := conn.WritePacket(http2TestPacket(t, src, dst, payload)); err != nil {
				return fmt.Errorf("packet %d: %w", i, err)
			}
		}
		return nil
	}
	// receive returns once the connection is closed, and fails on a torn or reordered packet.
	var closing atomic.Bool
	receive := func(conn *Conn, received *atomic.Int64) error {
		buf := make([]byte, 1500)
		next := uint64(0)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil {
				if closing.Load() {
					return nil
				}
				return fmt.Errorf("reading: %w", err)
			}
			payload := buf[ipv4.HeaderLen:n]
			if len(payload) != payloadLen {
				return fmt.Errorf("packet of %d bytes", n)
			}
			seq := binary.BigEndian.Uint64(payload)
			if seq < next {
				return fmt.Errorf("packet %d after %d", seq, next)
			}
			next = seq + 1
			for _, b := range payload[8:] {
				if b != byte(seq) {
					return fmt.Errorf("packet %d is corrupted", seq)
				}
			}
			received.Add(1)
		}
	}

	var fromClient, fromProxy atomic.Int64
	var receivers, senders sync.WaitGroup
	receivers.Go(func() {
		if err := receive(client, &fromProxy); err != nil {
			t.Error(err)
		}
	})
	receivers.Go(func() {
		if err := receive(proxy, &fromClient); err != nil {
			t.Error(err)
		}
	})
	senders.Go(func() {
		if err := send(client, http2ClientAddr, http2ProxyAddr); err != nil {
			t.Error(err)
		}
	})
	senders.Go(func() {
		if err := send(proxy, http2ProxyAddr, http2ClientAddr); err != nil {
			t.Error(err)
		}
	})

	// A capsule much larger than a DATA frame, in the middle of the datagrams.
	// It replaces the routes, so it needs to keep the one that the packets use.
	ranges := []IPRoute{{StartIP: http2ProxyAddr, EndIP: http2ProxyAddr}}
	for i := range routes - 1 {
		addr := netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)})
		ranges = append(ranges, IPRoute{StartIP: addr, EndIP: addr})
	}
	require.NoError(t, proxy.AdvertiseRoute(ranges))

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	got, err := client.Routes(ctx)
	require.NoError(t, err)
	require.Len(t, got, routes)
	// Control frames don't wait for the data.
	require.NoError(t, clientConn.Ping(ctx))

	senders.Wait()
	require.Eventually(t, func() bool {
		return fromClient.Load() > 0 && fromProxy.Load() > 0
	}, 5*time.Second, time.Millisecond)
	closing.Store(true)
	require.NoError(t, client.Close())
	receivers.Wait()
}

// stalledHTTP2Client opens a stream on a net/http server with almost no flow
// control credit, and never grants more: the writes of the handler can't complete.
// It returns the frames that the server sends.
func stalledHTTP2Client(t *testing.T, addr, path string) <-chan http2.Frame {
	t.Helper()
	conn := dialHTTP2(t, addr)
	_, err := io.WriteString(conn, http2.ClientPreface)
	require.NoError(t, err)
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(http2InitialTableSize, nil)
	require.NoError(t, fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1}))

	frames := make(chan http2.Frame, 1024)
	go func() {
		defer close(frames)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			select {
			case frames <- f:
			default:
			}
		}
	}()

	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range [][2]string{
		{":method", "CONNECT"},
		{":protocol", requestProtocol},
		{":scheme", "https"},
		{":authority", addr},
		{":path", path},
		{"capsule-protocol", capsuleProtocolHeaderValue},
	} {
		require.NoError(t, enc.WriteField(hpack.HeaderField{Name: field[0], Value: field[1]}))
	}
	require.NoError(t, fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}))
	return frames
}

// TestHTTP2CloseWithBlockedWrite checks what proxyBody relies on: closing a Conn while
// net/http can't send anything has to finish, and the handler can then return safely.
func TestHTTP2CloseWithBlockedWrite(t *testing.T) {
	conns := make(chan *Conn, 1)
	handlerDone := make(chan struct{})
	var template *uritemplate.Template
	addr := startHTTP2Server(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		servingProxy(t, func() *uritemplate.Template { return template }, conns)(w, r)
	}, nil)
	template = uritemplate.MustNew("https://" + addr + "/connect-ip")
	frames := stalledHTTP2Client(t, addr, "/connect-ip")

	var conn *Conn
	select {
	case conn = <-conns:
	case <-time.After(5 * time.Second):
		t.Fatal("no session on the proxy")
	}
	// This goes to net/http at once, where it waits for flow control.
	require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.PrefixFrom(http2ClientAddr, 32)}))
	s := conn.str.(*http2Stream)
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.pending) == 0
	}, 5*time.Second, time.Millisecond)

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn.Close()
	}()
	timeout := time.After(http2CloseTimeout + 5*time.Second)
	for _, done := range []chan struct{}{closed, handlerDone} {
		select {
		case <-done:
		case <-timeout:
			t.Fatal("closing the Conn didn't finish")
		}
	}

	for {
		select {
		case f, ok := <-frames:
			require.True(t, ok, "the connection closed without RST_STREAM")
			if rst, ok := f.(*http2.RSTStreamFrame); ok {
				require.Equal(t, http2.ErrCodeInternal, rst.ErrCode)
				return
			}
		case <-timeout:
			t.Fatal("no RST_STREAM from the server")
		}
	}
}
