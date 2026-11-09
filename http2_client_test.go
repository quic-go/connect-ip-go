package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const fakeHTTP2Timeout = 5 * time.Second

var extendedConnectSetting = http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}

// fakeHTTP2Proxy is the server end of an HTTP2ClientConn, one frame at a time.
// The connection is a net.Pipe, so that nothing is written until the other side reads.
type fakeHTTP2Proxy struct {
	t    *testing.T
	conn net.Conn
	fr   *http2.Framer
}

func newFakeHTTP2Proxy(t *testing.T, conf *HTTP2Config) (*fakeHTTP2Proxy, *HTTP2ClientConn) {
	t.Helper()
	clientSide, proxySide := net.Pipe()
	t.Cleanup(func() { proxySide.Close() })
	require.NoError(t, proxySide.SetDeadline(time.Now().Add(fakeHTTP2Timeout)))
	p := &fakeHTTP2Proxy{t: t, conn: proxySide, fr: http2.NewFramer(proxySide, proxySide)}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(http2InitialTableSize, nil)
	c := NewHTTP2ClientConn(clientSide, conf)
	t.Cleanup(func() { c.Close() })

	preface := make([]byte, len(http2.ClientPreface))
	_, err := io.ReadFull(proxySide, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface))
	return p, c
}

// handshake reads the settings of the client, and sends these settings.
func (p *fakeHTTP2Proxy) handshake(settings ...http2.Setting) {
	p.t.Helper()
	f, err := p.fr.ReadFrame()
	require.NoError(p.t, err)
	require.IsType(p.t, &http2.SettingsFrame{}, f)
	require.NoError(p.t, p.fr.WriteSettings(settings...))
}

// next reads the frames of the client until accept returns true.
// Frames are only valid during the call to accept.
func (p *fakeHTTP2Proxy) next(accept func(http2.Frame) bool) {
	p.t.Helper()
	for {
		f, err := p.fr.ReadFrame()
		require.NoError(p.t, err)
		if accept(f) {
			return
		}
	}
}

func nextFrame[T http2.Frame](p *fakeHTTP2Proxy) T {
	p.t.Helper()
	var frame T
	p.next(func(f http2.Frame) bool {
		var ok bool
		frame, ok = f.(T)
		return ok
	})
	return frame
}

func (p *fakeHTTP2Proxy) writeResponse(status string, endStream bool) {
	p.t.Helper()
	p.writeHeaders(endStream, hpack.HeaderField{Name: ":status", Value: status})
}

func (p *fakeHTTP2Proxy) writeHeaders(endStream bool, fields ...hpack.HeaderField) {
	p.t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range fields {
		require.NoError(p.t, enc.WriteField(field))
	}
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      http2StreamID,
		BlockFragment: block.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}))
}

// drain discards what the client writes, so that it can finish writing.
func (p *fakeHTTP2Proxy) drain() {
	go func() { io.Copy(io.Discard, p.conn) }()
}

func (c *HTTP2ClientConn) waitForFailure(t *testing.T) error {
	t.Helper()
	select {
	case <-c.done:
		return c.failure()
	case <-time.After(fakeHTTP2Timeout):
		t.Fatal("the connection didn't fail")
		return nil
	}
}

func newHTTP2TestRequest(t *testing.T, ctx context.Context) *Request {
	t.Helper()
	req, err := NewRequest(ctx, uritemplate.MustNew("https://proxy.example:443/connect-ip?epoch=1"))
	require.NoError(t, err)
	return req
}

type http2DialResult struct {
	conn *Conn
	rsp  *http.Response
	err  error
}

func dialAsync(t *testing.T, ctx context.Context, c *HTTP2ClientConn) <-chan http2DialResult {
	t.Helper()
	req := newHTTP2TestRequest(t, ctx)
	result := make(chan http2DialResult, 1)
	go func() {
		conn, rsp, err := c.Dial(req)
		result <- http2DialResult{conn, rsp, err}
	}()
	return result
}

// establish goes through the handshake and a successful Dial.
func (p *fakeHTTP2Proxy) establish(c *HTTP2ClientConn, settings ...http2.Setting) *Conn {
	p.t.Helper()
	result := dialAsync(p.t, p.t.Context(), c)
	p.handshake(append(settings, extendedConnectSetting)...)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("200", false)
	r := <-result
	require.NoError(p.t, r.err)
	p.t.Cleanup(func() {
		p.drain()
		r.conn.Close()
	})
	return r.conn
}

// skipDial lets the proxy send DATA without anything reading it, unlike a Conn.
func (c *HTTP2ClientConn) skipDial() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialed = true
	c.responded = true
}

func TestHTTP2ClientRequest(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	req := newHTTP2TestRequest(t, t.Context())
	req.Header().Set("Authorization", "Bearer token")
	// Connection-specific header fields don't exist in HTTP/2: RFC 9113, section 8.2.2.
	req.Header().Set("Connection", "keep-alive")
	req.Header().Set("Keep-Alive", "timeout=5")
	go c.Dial(req)
	p.handshake(extendedConnectSetting)

	headers := nextFrame[*http2.MetaHeadersFrame](p)
	require.Equal(t, uint32(http2StreamID), headers.StreamID)
	require.False(t, headers.StreamEnded(), "the stream carries the capsules of the client")
	require.Equal(t, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: requestProtocol},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "proxy.example:443"},
		{Name: ":path", Value: "/connect-ip?epoch=1"},
	}, headers.PseudoFields())
	require.ElementsMatch(t, []hpack.HeaderField{
		{Name: "capsule-protocol", Value: capsuleProtocolHeaderValue},
		{Name: "authorization", Value: "Bearer token"},
	}, headers.RegularFields())
}

func TestHTTP2ClientSettings(t *testing.T) {
	p, _ := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: 1 << 20})
	settings := nextFrame[*http2.SettingsFrame](p)
	window, ok := settings.Value(http2.SettingInitialWindowSize)
	require.True(t, ok)
	require.EqualValues(t, 1<<20, window)
	push, ok := settings.Value(http2.SettingEnablePush)
	require.True(t, ok)
	require.Zero(t, push)

	update := nextFrame[*http2.WindowUpdateFrame](p)
	require.Zero(t, update.StreamID)
	require.EqualValues(t, 1<<20-http2InitialWindow, update.Increment)
}

func TestHTTP2ClientReceiveWindowLimits(t *testing.T) {
	for name, tc := range map[string]struct {
		conf *HTTP2Config
		want int64
	}{
		"default": {nil, defaultHTTP2ReceiveWindow},
		"unset":   {&HTTP2Config{}, defaultHTTP2ReceiveWindow},
		"too low": {&HTTP2Config{ReceiveWindow: 1}, http2InitialWindow},
		"too big": {&HTTP2Config{ReceiveWindow: 1 << 40}, http2MaxWindow},
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newFakeHTTP2Proxy(t, tc.conf)
			require.Equal(t, tc.want, c.window)
		})
	}
}

func TestHTTP2ClientWithoutExtendedConnect(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake()
	nextFrame[*http2.SettingsFrame](p) // the ACK
	r := <-result
	require.ErrorContains(t, r.err, "server didn't enable Extended CONNECT")
}

func TestHTTP2ClientDialWaitsForSettings(t *testing.T) {
	_, c := newFakeHTTP2Proxy(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	r := <-dialAsync(t, ctx, c)
	require.ErrorIs(t, r.err, context.DeadlineExceeded)
}

func TestHTTP2ClientDialCanceled(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	result := dialAsync(t, ctx, c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	cancel()
	require.ErrorIs(t, (<-result).err, context.Canceled)

	rst := nextFrame[*http2.RSTStreamFrame](p)
	require.Equal(t, http2.ErrCodeCancel, rst.ErrCode)
}

func TestHTTP2ClientDialOnce(t *testing.T) {
	t.Run("after a session", func(t *testing.T) {
		p, c := newFakeHTTP2Proxy(t, nil)
		p.establish(c)
		r := <-dialAsync(t, t.Context(), c)
		require.ErrorContains(t, r.err, "already used")
	})
	t.Run("after a canceled call", func(t *testing.T) {
		_, c := newFakeHTTP2Proxy(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		r := <-dialAsync(t, ctx, c)
		require.ErrorIs(t, r.err, context.Canceled)
		r = <-dialAsync(t, t.Context(), c)
		require.ErrorContains(t, r.err, "already used")
	})
}

func TestHTTP2ClientInvalidHeader(t *testing.T) {
	for name, header := range map[string][2]string{
		"name":  {"Bad Name", "value"},
		"value": {"Name", "bad\x00value"},
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newFakeHTTP2Proxy(t, nil)
			req := newHTTP2TestRequest(t, t.Context())
			req.Header()[header[0]] = []string{header[1]}
			_, _, err := c.Dial(req)
			require.ErrorContains(t, err, "invalid")
		})
	}
}

func TestHTTP2ClientRequestHeadersTooLarge(t *testing.T) {
	_, c := newFakeHTTP2Proxy(t, nil)
	req := newHTTP2TestRequest(t, t.Context())
	req.Header().Set("Too-Large", string(bytes.Repeat([]byte("x"), 2*http2InitialMaxFrameSize)))
	_, _, err := c.Dial(req)
	require.ErrorContains(t, err, "request headers too large")
}

func TestHTTP2ClientRefused(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("403", true)
	r := <-result
	require.ErrorContains(t, r.err, "server responded with 403")
	require.Nil(t, r.conn)
	require.Equal(t, http.StatusForbidden, r.rsp.StatusCode)
	require.Equal(t, "403 Forbidden", r.rsp.Status)
	require.NotNil(t, r.rsp.Request)
	require.Equal(t, http.NoBody, r.rsp.Body)

	rst := nextFrame[*http2.RSTStreamFrame](p)
	require.Equal(t, http2.ErrCodeCancel, rst.ErrCode)
}

func TestHTTP2ClientRefusedThenClosed(t *testing.T) {
	// The refusal must not get lost in the failure of the connection that follows it.
	for range 20 {
		p, c := newFakeHTTP2Proxy(t, nil)
		req := newHTTP2TestRequest(t, t.Context())
		p.handshake(extendedConnectSetting)
		nextFrame[*http2.SettingsFrame](p)
		c.mu.Lock()
		c.dialed = true
		c.mu.Unlock()
		p.writeResponse("403", false)
		p.conn.Close()
		require.Error(t, c.waitForFailure(t))
		rsp, err := c.waitForResponse(req.httpRequest().Context())
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, rsp.StatusCode)
	}
}

func TestHTTP2ClientIgnoresInterimResponses(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("103", false)
	p.writeResponse("200", false)
	r := <-result
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.rsp.StatusCode)
	p.drain()
	require.NoError(t, r.conn.Close())
}

func TestHTTP2ClientMalformed(t *testing.T) {
	for name, tc := range map[string]struct {
		send func(*fakeHTTP2Proxy)
		want string
	}{
		"PING before SETTINGS": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WritePing(false, [8]byte{})) },
			"expected a SETTINGS frame",
		},
		"SETTINGS ACK before SETTINGS": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteSettingsAck()) },
			"expected a SETTINGS frame",
		},
		"invalid setting": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 2}))
			},
			"invalid setting",
		},
		"HEADERS without a request": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				p.writeResponse("200", false)
			},
			"unexpected HEADERS",
		},
		"DATA without a request": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				require.NoError(p.t, p.fr.WriteData(http2StreamID, false, []byte("data")))
			},
			"unexpected DATA",
		},
		"GOAWAY rejecting the stream": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				require.NoError(p.t, p.fr.WriteGoAway(0, http2.ErrCodeNo, nil))
			},
			"GOAWAY",
		},
		"GOAWAY with an error": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				require.NoError(p.t, p.fr.WriteGoAway(http2StreamID, http2.ErrCodeProtocol, nil))
			},
			"GOAWAY",
		},
		"not HTTP/2": {
			func(p *fakeHTTP2Proxy) {
				// The client gives up after reading a frame header: this write can fail.
				_, _ = io.WriteString(p.conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
			},
			"reading from the proxy",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			p.drain()
			tc.send(p)
			require.ErrorContains(t, c.waitForFailure(t), tc.want)

			r := <-dialAsync(t, t.Context(), c)
			require.ErrorContains(t, r.err, tc.want)
		})
	}
}

func TestHTTP2ClientInvalidStatus(t *testing.T) {
	// RFC 9113, section 8.3.2: a 3-digit code, which strconv alone would read more liberally.
	for _, status := range []string{"+20", "0200", "20", "2O0"} {
		t.Run(status, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			result := dialAsync(t, t.Context(), c)
			p.handshake(extendedConnectSetting)
			nextFrame[*http2.MetaHeadersFrame](p)
			p.writeResponse(status, false)
			require.ErrorContains(t, (<-result).err, "invalid status")
		})
	}
}

func TestHTTP2ClientWindowOverflow(t *testing.T) {
	flowControlError := http2.ConnectionError(http2.ErrCodeFlowControl)
	for name, send := range map[string]func(*fakeHTTP2Proxy){
		"connection": func(p *fakeHTTP2Proxy) {
			require.NoError(p.t, p.fr.WriteWindowUpdate(0, http2MaxWindow))
		},
		"stream": func(p *fakeHTTP2Proxy) {
			require.NoError(p.t, p.fr.WriteWindowUpdate(http2StreamID, http2MaxWindow))
		},
		"setting": func(p *fakeHTTP2Proxy) {
			require.NoError(p.t, p.fr.WriteWindowUpdate(http2StreamID, http2MaxWindow-http2InitialWindow))
			require.NoError(p.t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: http2InitialWindow + 1}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			p.drain()
			require.NoError(t, p.fr.WriteSettings())
			c.skipDial() // the stream has to exist for its window to be updated
			send(p)
			require.ErrorIs(t, c.waitForFailure(t), flowControlError)
		})
	}
}

func TestHTTP2ClientGoAwayWithoutRejection(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	require.NoError(t, p.fr.WriteGoAway(http2StreamID, http2.ErrCodeNo, nil))
	require.NoError(t, p.fr.WritePing(false, [8]byte{})) // the client handled the GOAWAY
	require.NoError(t, c.failure())

	require.NoError(t, conn.sendCapsule(&routeAdvertisementCapsule{}))
	require.NotNil(t, nextFrame[*http2.DataFrame](p))
}

func TestHTTP2ClientStreamReset(t *testing.T) {
	t.Run("during the request", func(t *testing.T) {
		p, c := newFakeHTTP2Proxy(t, nil)
		result := dialAsync(t, t.Context(), c)
		p.handshake(extendedConnectSetting)
		nextFrame[*http2.MetaHeadersFrame](p)
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeRefusedStream))
		require.ErrorContains(t, (<-result).err, "REFUSED_STREAM")
	})

	t.Run("during the session", func(t *testing.T) {
		p, c := newFakeHTTP2Proxy(t, nil)
		conn := p.establish(c)
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeInternal))
		_, err := conn.ReadPacket(make([]byte, 1500))
		require.ErrorIs(t, err, net.ErrClosed)
		require.ErrorContains(t, c.failure(), "INTERNAL_ERROR")
	})

	t.Run("after the response", func(t *testing.T) {
		// This is how net/http ends a stream when its handler returns.
		p, c := newFakeHTTP2Proxy(t, nil)
		p.drain()
		require.NoError(t, p.fr.WriteSettings())
		c.skipDial()
		require.NoError(t, p.fr.WriteData(http2StreamID, true, []byte("data")))
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeNo))
		require.NoError(t, p.fr.WritePing(false, [8]byte{})) // the client handled the reset

		body := &clientBody{c: c}
		got, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Equal(t, "data", string(got))
		require.NoError(t, c.failure())

		n, err := body.Write([]byte("data"))
		require.ErrorIs(t, err, net.ErrClosed)
		require.Zero(t, n)
	})
}

func TestHTTP2ClientRespectsFlowControl(t *testing.T) {
	const window = 100
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c, http2.Setting{ID: http2.SettingInitialWindowSize, Val: window})

	received := func(want int) {
		t.Helper()
		var got int
		for got < want {
			f := nextFrame[*http2.DataFrame](p)
			got += len(f.Data())
		}
		require.Equal(t, want, got)
	}
	nothingMore := func() {
		t.Helper()
		require.NoError(t, p.conn.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
		_, err := p.conn.Read(make([]byte, 1))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.NoError(t, p.conn.SetDeadline(time.Now().Add(fakeHTTP2Timeout)))
	}

	data := appendTestCapsule(nil, 0x41, string(make([]byte, 2*window)))
	_, err := conn.str.Write(data)
	require.NoError(t, err)
	received(window)
	nothingMore()

	// The stream's window opens through the settings, and can even go negative.
	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window - 50}))
	nextFrame[*http2.SettingsFrame](p)
	nothingMore()
	require.NoError(t, p.fr.WriteWindowUpdate(http2StreamID, 60))
	received(10)
	nothingMore()

	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: http2InitialWindow}))
	received(len(data) - window - 10)
	c.mu.Lock()
	sent := http2InitialWindow - c.connSend
	c.mu.Unlock()
	require.EqualValues(t, len(data), sent)
}

func TestHTTP2ClientRespectsConnectionWindow(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})

	data := appendTestCapsule(nil, 0x41, string(make([]byte, 2*http2InitialWindow)))
	_, err := conn.str.Write(data)
	require.NoError(t, err)
	var got int
	for got < http2InitialWindow {
		got += len(nextFrame[*http2.DataFrame](p).Data())
	}
	require.Equal(t, http2InitialWindow, got)
	require.NoError(t, p.conn.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
	_, err = p.conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, p.conn.SetDeadline(time.Now().Add(fakeHTTP2Timeout)))

	require.NoError(t, p.fr.WriteWindowUpdate(0, 1<<20))
	for got < len(data) {
		got += len(nextFrame[*http2.DataFrame](p).Data())
	}
	require.Equal(t, len(data), got)
}

func TestHTTP2ClientRespectsMaxFrameSize(t *testing.T) {
	const maxFrame = 1 << 15
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c, http2.Setting{ID: http2.SettingMaxFrameSize, Val: maxFrame})

	data := appendTestCapsule(nil, 0x41, string(make([]byte, 3*maxFrame)))
	_, err := conn.str.Write(data)
	require.NoError(t, err)
	require.Len(t, nextFrame[*http2.DataFrame](p).Data(), maxFrame)
}

func TestHTTP2ClientRespectsLoweredMaxFrameSize(t *testing.T) {
	const maxFrame = 2 * http2InitialMaxFrameSize
	p, c := newFakeHTTP2Proxy(t, nil)
	p.establish(c, http2.Setting{ID: http2.SettingMaxFrameSize, Val: maxFrame})
	n, err := c.reserve(maxFrame)
	require.NoError(t, err)
	require.Equal(t, maxFrame, n)

	// The proxy lowers the limit after the reservation, and the acknowledgment goes out before the DATA.
	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: http2InitialMaxFrameSize}))
	require.True(t, nextFrame[*http2.SettingsFrame](p).IsAck())
	done := make(chan error, 1)
	go func() { done <- c.writeData(make([]byte, n)) }()
	for range 2 {
		require.Len(t, nextFrame[*http2.DataFrame](p).Data(), http2InitialMaxFrameSize)
	}
	require.NoError(t, <-done)
}

func TestHTTP2ClientResetInterruptsBlockedWrite(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	// The proxy doesn't read: the DATA frame blocks in the network.
	_, err := conn.str.Write(appendTestCapsule(nil, 0x41, "capsule"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.writing
	}, time.Second, time.Millisecond)

	// Resetting the stream can't wait for that write, and interrupting it ends the connection.
	conn.str.CancelWrite(0)
	err = c.waitForFailure(t)
	require.ErrorContains(t, err, "writing to the proxy")
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	select {
	case <-conn.str.(*http2Stream).flushed:
	case <-time.After(fakeHTTP2Timeout):
		t.Fatal("the flush loop didn't return")
	}
}

// nextCredit reads the credit that the client grants, which has to be the same on both levels.
func (p *fakeHTTP2Proxy) nextCredit() uint32 {
	p.t.Helper()
	connection := nextFrame[*http2.WindowUpdateFrame](p)
	require.Zero(p.t, connection.StreamID)
	stream := nextFrame[*http2.WindowUpdateFrame](p)
	require.Equal(p.t, uint32(http2StreamID), stream.StreamID)
	require.Equal(p.t, connection.Increment, stream.Increment)
	return stream.Increment
}

func TestHTTP2ClientCreditsWhatItReads(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	p.establish(c)

	const frames, frameLen = 3, http2InitialMaxFrameSize
	// One capsule of an unknown type, which Conn reads and ignores.
	const headerLen = 2 + 4
	header := quicvarint.AppendWithLen(quicvarint.Append(nil, 0x41), frames*frameLen-headerLen, 4)
	frame := make([]byte, frameLen)
	copy(frame, header)
	require.NoError(t, p.fr.WriteData(http2StreamID, false, frame))
	for range frames - 1 {
		require.NoError(t, p.fr.WriteData(http2StreamID, false, make([]byte, frameLen)))
	}
	// The credit comes in batches of at least half the window.
	credit := p.nextCredit()
	require.GreaterOrEqual(t, credit, uint32(http2InitialWindow/2))
	require.LessOrEqual(t, credit, uint32(frames*frameLen))
}

func TestHTTP2ClientCreditsPadding(t *testing.T) {
	// Flow control covers padding, which no reader is ever going to consume.
	const frameLen = 256 // with the Pad Length field
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	p.establish(c)
	frames := (http2InitialWindow/2)/frameLen + 1
	for range frames {
		require.NoError(t, p.fr.WriteDataPadded(http2StreamID, false, nil, make([]byte, frameLen-1)))
	}
	require.Equal(t, uint32(frames*frameLen), p.nextCredit())
}

func TestHTTP2ClientFlowControlViolation(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	p.drain()
	require.NoError(t, p.fr.WriteSettings())
	c.skipDial()
	frame := make([]byte, http2InitialMaxFrameSize)
	for range http2InitialWindow / len(frame) {
		require.NoError(t, p.fr.WriteData(http2StreamID, false, frame))
	}
	require.NoError(t, p.fr.WriteData(http2StreamID, false, frame[:http2InitialWindow%len(frame)]))
	require.NoError(t, p.fr.WriteData(http2StreamID, false, []byte{0}))
	require.ErrorIs(t, c.waitForFailure(t), http2.ConnectionError(http2.ErrCodeFlowControl))
}

func TestHTTP2ClientDropsDataAfterCloseRead(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	require.NoError(t, p.fr.WriteSettings())
	nextFrame[*http2.SettingsFrame](p)
	c.skipDial()
	body := &clientBody{c: c}
	body.CloseRead()
	_, err := body.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)

	// Nobody reads it, but it's credited all the same: twice the window goes through.
	frame := make([]byte, http2InitialMaxFrameSize)
	var sent, credited int
	for sent < 2*http2InitialWindow {
		require.NoError(t, p.fr.WriteData(http2StreamID, false, frame))
		sent += len(frame)
		if sent-credited >= http2InitialWindow/2 {
			credited += int(p.nextCredit())
		}
	}
	require.Equal(t, sent, credited)
	require.NoError(t, c.failure())
}

func TestHTTP2ClientWindowOnlyWidensWithTransmittedCredit(t *testing.T) {
	// The proxy never reads: the first WINDOW_UPDATE blocks the writer. The credit for
	// the padding that follows can't reach it, so the padding counts against the window.
	const frameLen = 256 // with the Pad Length field
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	require.NoError(t, p.fr.WriteSettings())
	nextFrame[*http2.SettingsFrame](p)
	c.skipDial()
	for range 3 * http2InitialWindow / frameLen {
		if err := p.fr.WriteDataPadded(http2StreamID, false, nil, make([]byte, frameLen-1)); err != nil {
			break // the client closed the connection
		}
	}
	require.ErrorIs(t, c.waitForFailure(t), http2.ConnectionError(http2.ErrCodeFlowControl))
	// A single WINDOW_UPDATE waits, whatever the proxy sent, behind the SETTINGS ACK
	// if the writer hasn't taken it yet.
	c.mu.Lock()
	defer c.mu.Unlock()
	require.LessOrEqual(t, len(c.control), 2)
}

func TestHTTP2ClientEndOfStream(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.drain()
	require.NoError(t, p.fr.WriteSettings())
	c.skipDial()
	require.NoError(t, p.fr.WriteData(http2StreamID, true, []byte("data")))

	got, err := io.ReadAll(&clientBody{c: c})
	require.NoError(t, err)
	require.Equal(t, "data", string(got))
}

func TestHTTP2ClientTrailers(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	p.writeHeaders(true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
	_, err := conn.ReadPacket(make([]byte, 1500))
	var closeErr *CloseError
	require.ErrorAs(t, err, &closeErr)
	require.True(t, closeErr.Remote)
	require.NoError(t, c.failure(), "the trailers were valid")
}

func TestHTTP2ClientStreamViolations(t *testing.T) {
	endStream := func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteData(http2StreamID, true, nil)) }
	for name, tc := range map[string]struct {
		send func(*fakeHTTP2Proxy)
		want http2.ErrCode
	}{
		"trailers with a pseudo-header": {
			func(p *fakeHTTP2Proxy) { p.writeResponse("200", true) },
			http2.ErrCodeProtocol,
		},
		"trailers without END_STREAM": {
			func(p *fakeHTTP2Proxy) { p.writeHeaders(false, hpack.HeaderField{Name: "x-trailer", Value: "1"}) },
			http2.ErrCodeProtocol,
		},
		"DATA after END_STREAM": {
			func(p *fakeHTTP2Proxy) {
				endStream(p)
				require.NoError(p.t, p.fr.WriteData(http2StreamID, false, []byte{0}))
			},
			http2.ErrCodeStreamClosed,
		},
		"HEADERS after END_STREAM": {
			func(p *fakeHTTP2Proxy) {
				endStream(p)
				p.writeHeaders(true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
			},
			http2.ErrCodeStreamClosed,
		},
		"WINDOW_UPDATE on an idle stream": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteWindowUpdate(3, 1)) },
			http2.ErrCodeProtocol,
		},
		"RST_STREAM on an idle stream": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteRSTStream(3, http2.ErrCodeNo)) },
			http2.ErrCodeProtocol,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			p.establish(c)
			tc.send(p)
			require.ErrorIs(t, c.waitForFailure(t), http2.ConnectionError(tc.want))
		})
	}
}

func TestHTTP2ClientCloseSendsEndStream(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	p.next(func(f http2.Frame) bool {
		data, ok := f.(*http2.DataFrame)
		return ok && data.StreamEnded()
	})
	require.NoError(t, <-done)
}

func TestHTTP2ClientAnswersProxy(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.establish(c, http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})

	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	require.NoError(t, p.fr.WritePing(false, data))
	ping := nextFrame[*http2.PingFrame](p)
	require.True(t, ping.IsAck())
	require.Equal(t, data, ping.Data)
}

func TestHTTP2ClientControlFramesDoNotWaitForData(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	// The proxy doesn't read: the DATA frame blocks in the network.
	_, err := conn.str.Write(appendTestCapsule(nil, 0x41, "capsule"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		if !c.wmu.TryLock() {
			return true
		}
		c.wmu.Unlock()
		return false
	}, time.Second, time.Millisecond)

	// The read loop keeps going, however, or the proxy couldn't send this. If it
	// waited for the write, the proxy's own writes would block too: that's a deadlock.
	for range maxQueuedHTTP2ControlFrames {
		require.NoError(t, p.fr.WritePing(false, [8]byte{}))
	}
	// Until the control queue is full, with one frame in the hands of the writer: the proxy is abusing it.
	for range 2 {
		_ = p.fr.WritePing(false, [8]byte{})
	}
	require.ErrorContains(t, c.waitForFailure(t), "doesn't read its control frames")
}

func TestHTTP2ClientPing(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.handshake()
	nextFrame[*http2.SettingsFrame](p)

	errChan := make(chan error, 1)
	go func() { errChan <- c.Ping(t.Context()) }()
	ping := nextFrame[*http2.PingFrame](p)
	require.False(t, ping.IsAck())
	require.NoError(t, p.fr.WritePing(true, [8]byte{0xff})) // not an answer to this ping
	select {
	case <-errChan:
		t.Fatal("Ping returned")
	case <-time.After(10 * time.Millisecond):
	}
	require.NoError(t, p.fr.WritePing(true, ping.Data))
	require.NoError(t, <-errChan)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	p.drain()
	require.ErrorIs(t, c.Ping(ctx), context.DeadlineExceeded)
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Empty(t, c.pings)
}

func TestHTTP2ClientPingQueueIsBounded(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.handshake()
	// The proxy reads nothing else: the SETTINGS ACK blocks the writer, and the PING frames queue up.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var err error
	for range maxQueuedHTTP2ControlFrames + 2 {
		if err = c.Ping(ctx); !errors.Is(err, context.Canceled) {
			break
		}
	}
	require.ErrorContains(t, err, "doesn't read its control frames")
	require.NoError(t, c.failure(), "whether to give up on the connection is the caller's call")
}

func TestHTTP2ClientPingOnFailedConnection(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.drain()
	errChan := make(chan error, 1)
	go func() { errChan <- c.Ping(t.Context()) }()
	p.conn.Close()
	require.Error(t, <-errChan)
	require.Error(t, c.Ping(t.Context()))
}

func TestHTTP2ClientWriteFailure(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	p.conn.Close()
	_, err := (&clientBody{c: c}).Write([]byte("data"))
	require.Error(t, err)
	require.Error(t, c.waitForFailure(t))
	_, err = conn.ReadPacket(make([]byte, 1500))
	require.True(t, errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe), "%v", err)
}

func TestHTTP2ClientConnReset(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	code := quic.StreamErrorCode(http3.ErrCodeExcessiveLoad)
	conn.str.CancelWrite(code)
	rst := nextFrame[*http2.RSTStreamFrame](p)
	require.Equal(t, http2.ErrCodeEnhanceYourCalm, rst.ErrCode)
	conn.str.CancelWrite(code)
	n, err := (&clientBody{c: c}).Write([]byte("data"))
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, n)
}

// brokenWritesConn is a connection the peer closed: writes fail at once, and
// reads report what the peer sent last, once read is closed.
type brokenWritesConn struct {
	net.Conn
	read chan struct{}
}

func (c *brokenWritesConn) Read([]byte) (int, error) {
	<-c.read
	return 0, errors.New("remote error: tls: bad certificate")
}

func (c *brokenWritesConn) Write([]byte) (int, error) { return 0, errors.New("write: broken pipe") }

func (c *brokenWritesConn) Close() error { return nil }

func TestHTTP2ClientReportsWhyWritesBroke(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &brokenWritesConn{read: make(chan struct{})}
		c := NewHTTP2ClientConn(conn, nil)
		written := make(chan error, 1)
		go func() {
			_, err := (&clientBody{c: c}).Write([]byte("data"))
			written <- err
		}()
		// Both writers have failed: neither may report it yet.
		synctest.Wait()
		select {
		case <-c.done:
			t.Fatal("a failed write ended the connection before the read loop could say why")
		default:
		}
		close(conn.read)
		require.ErrorContains(t, <-written, "bad certificate")
		require.ErrorContains(t, c.failure(), "bad certificate")
	})
}

func TestHTTP2ClientWriteFailureIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &brokenWritesConn{read: make(chan struct{})}
		defer close(conn.read)
		c := NewHTTP2ClientConn(conn, nil)
		start := time.Now()
		<-c.done
		require.Equal(t, http2WriteFailureGrace, time.Since(start))
		require.ErrorContains(t, c.failure(), "broken pipe")
	})
}
