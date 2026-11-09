package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// http2StreamID is the stream of the proxied connection: the first one a client opens.
	http2StreamID = 1
	// Initial values of RFC 9113, section 6.5.2.
	http2InitialWindow       = 65535
	http2InitialMaxFrameSize = 16384
	http2InitialTableSize    = 4096
	// http2MaxWindow is the largest flow control window of RFC 9113, section 6.9.1.
	http2MaxWindow = 1<<31 - 1

	defaultHTTP2ReceiveWindow = 4 << 20
	maxHTTP2HeaderListSize    = 1 << 16
	// maxQueuedHTTP2ControlFrames bounds the answers owed to a proxy that doesn't read them.
	maxQueuedHTTP2ControlFrames = 128

	// http2WriteFailureGrace is how long a failed write waits for the read loop to report why.
	http2WriteFailureGrace = time.Second
)

// HTTP2Config configures an [HTTP2ClientConn].
type HTTP2Config struct {
	// ReceiveWindow is the HTTP/2 flow control window of the proxied connection, in bytes.
	// It limits the throughput from the proxy to this window per round trip.
	// The default is 4 MiB. Values below 65535 and above 2^31-1 are raised, or lowered, to these.
	ReceiveWindow int64
}

// An HTTP2ClientConn is an HTTP/2 connection to a proxy, for networks that block UDP.
// It carries a single proxied connection, since it is its own HTTP/2 client:
// neither net/http nor golang.org/x/net/http2 can send the :protocol pseudo-header
// that Extended CONNECT (RFC 8441) needs, see https://go.dev/issue/53208.
//
// HTTP/2 runs over TCP, so a proxied connection is subject to TCP's retransmissions
// and head-of-line blocking. HTTP/3 should be preferred whenever it is available.
type HTTP2ClientConn struct {
	nc     net.Conn
	fr     *http2.Framer
	window int64

	settings chan struct{}       // closed when the first SETTINGS frame arrives
	response chan *http.Response // receives the response to Dial
	done     chan struct{}       // closed when the connection fails, after setting err

	// wmu serializes the frames, and is held while the network blocks a write.
	// The read loop must never wait for it: if both peers stopped reading
	// because their writes are blocked, none of these writes would finish.
	wmu sync.Mutex

	mu              sync.Mutex
	cond            *sync.Cond
	err             error
	control         []func(*http2.Framer) error // frames owed to the proxy, written ahead of DATA frames
	sawSettings     bool
	extendedConnect bool
	noStreams       bool // the proxy's SETTINGS_MAX_CONCURRENT_STREAMS is 0
	dialing         bool // Dial was called
	dialed          bool // the request was sent
	responded       bool
	writing         bool // a DATA frame is being written, and may be blocked in the network
	pingID          uint64
	pings           map[[8]byte]chan struct{}
	connSend        int64 // connection-level send window
	streamSend      int64 // stream-level send window
	initialSend     int64 // the proxy's SETTINGS_INITIAL_WINDOW_SIZE
	maxFrame        int64 // the proxy's SETTINGS_MAX_FRAME_SIZE
	sendClosed      bool
	resetSent       bool
	recv            bytes.Buffer
	recvEnded       bool  // the proxy ended the stream
	recvClosed      bool  // the local side stopped reading
	recvUsed        int64 // bytes the proxy sent, until the writer takes their credit
	recvCredit      int64 // the part of recvUsed that was consumed, and can be credited
	creditQueued    bool  // a WINDOW_UPDATE for recvCredit waits in control
}

// NewHTTP2ClientConn starts an HTTP/2 connection on conn, a TLS connection that negotiated
// the "h2" ALPN. The caller owns conn until calling Close, which closes it.
// Failures surface on [HTTP2ClientConn.Dial], or on the proxied connection after that.
func NewHTTP2ClientConn(conn net.Conn, conf *HTTP2Config) *HTTP2ClientConn {
	window := int64(defaultHTTP2ReceiveWindow)
	if conf != nil && conf.ReceiveWindow != 0 {
		window = min(max(conf.ReceiveWindow, http2InitialWindow), http2MaxWindow)
	}
	c := &HTTP2ClientConn{
		nc:          conn,
		fr:          http2.NewFramer(conn, conn),
		window:      window,
		settings:    make(chan struct{}),
		response:    make(chan *http.Response, 1),
		done:        make(chan struct{}),
		pings:       make(map[[8]byte]chan struct{}),
		connSend:    http2InitialWindow,
		streamSend:  http2InitialWindow,
		initialSend: http2InitialWindow,
		maxFrame:    http2InitialMaxFrameSize,
	}
	c.cond = sync.NewCond(&c.mu)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(http2InitialTableSize, nil)
	c.fr.MaxHeaderListSize = maxHTTP2HeaderListSize
	c.fr.SetMaxReadFrameSize(http2InitialMaxFrameSize)
	c.control = append(c.control, c.writePreface)
	go c.writeControlFrames()
	go c.readFrames()
	return c
}

func (c *HTTP2ClientConn) writePreface(fr *http2.Framer) error {
	if _, err := io.WriteString(c.nc, http2.ClientPreface); err != nil {
		return err
	}
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(c.window)},
	); err != nil {
		return err
	}
	if c.window == http2InitialWindow {
		return nil
	}
	return fr.WriteWindowUpdate(0, uint32(c.window-http2InitialWindow))
}

// Dial sends the request and waits for the response. The response comes back
// whenever the proxy answered, for the caller to read the status of a refusal.
// An HTTP2ClientConn can only be used for one call to Dial, even if it fails.
// Closing the returned Conn doesn't close the HTTP2ClientConn.
func (c *HTTP2ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}
	headers, err := encodeHTTP2Request(httpReq)
	if err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	if c.dialing {
		c.mu.Unlock()
		return nil, nil, errors.New("connect-ip: HTTP2ClientConn already used")
	}
	c.dialing = true
	c.mu.Unlock()

	ctx := httpReq.Context()
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-c.done:
		return nil, nil, c.failure()
	case <-c.settings:
	}

	c.mu.Lock()
	if err := c.err; err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	if !c.extendedConnect {
		c.mu.Unlock()
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	if c.noStreams {
		// Opening the stream would break the limit. The proxy may raise it later, but this
		// connection only carries one stream: better to dial another one than to wait.
		c.mu.Unlock()
		return nil, nil, errors.New("connect-ip: server accepts no streams (SETTINGS_MAX_CONCURRENT_STREAMS is 0)")
	}
	c.dialed = true
	c.queueControlFrame(func(fr *http2.Framer) error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      http2StreamID,
			BlockFragment: headers,
			EndHeaders:    true,
		})
	})
	c.mu.Unlock()

	rsp, err := c.waitForResponse(ctx)
	if err != nil {
		return nil, nil, err
	}
	rsp.Request = httpReq
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		c.reset(http2.ErrCodeCancel)
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(newHTTP2Stream(&clientBody{c: c}), nil), rsp, nil
}

func encodeHTTP2Request(req *http.Request) ([]byte, error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	// There's only one request: the dynamic table couldn't be reused, and the proxy could have shrunk it.
	enc.SetMaxDynamicTableSize(0)
	// Writing to a bytes.Buffer doesn't fail.
	write := func(name, value string) { _ = enc.WriteField(hpack.HeaderField{Name: name, Value: value}) }
	write(":method", req.Method)
	write(":protocol", req.Proto)
	write(":scheme", req.URL.Scheme)
	write(":authority", host)
	write(":path", req.URL.RequestURI())
	for name, values := range req.Header {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("connect-ip: invalid header field name %q", name)
		}
		name = strings.ToLower(name)
		// RFC 9113, section 8.2.2: HTTP/2 has no connection-specific header fields.
		// net/http drops them, and a server rejects a request that carries them.
		switch name {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			continue
		case "te":
			// The exception, which can only say "trailers".
			if httpguts.HeaderValuesContainsToken(values, "trailers") {
				write(name, "trailers")
			}
			continue
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("connect-ip: invalid value for header field %q", name)
			}
			write(name, value)
		}
	}
	if block.Len() > http2InitialMaxFrameSize {
		return nil, errors.New("connect-ip: request headers too large")
	}
	return block.Bytes(), nil
}

func (c *HTTP2ClientConn) waitForResponse(ctx context.Context) (*http.Response, error) {
	select {
	case rsp := <-c.response:
		return rsp, nil
	case <-ctx.Done():
		c.reset(http2.ErrCodeCancel)
		return nil, context.Cause(ctx)
	case <-c.done:
		// The proxy might have closed the connection right after refusing the request.
		select {
		case rsp := <-c.response:
			return rsp, nil
		default:
			return nil, c.failure()
		}
	}
}

// Ping checks that the proxy answers. It is the way to detect a dead path:
// TCP can take many minutes to give up, and its keep-alives stop while data is unacknowledged.
func (c *HTTP2ClientConn) Ping(ctx context.Context) error {
	ack := make(chan struct{})
	var id [8]byte

	c.mu.Lock()
	if err := c.err; err != nil {
		c.mu.Unlock()
		return err
	}
	// A Ping that times out leaves its frame behind: don't let them pile up on a writer that stalled.
	if err := c.checkControlQueue(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.pingID++
	binary.BigEndian.PutUint64(id[:], c.pingID)
	c.pings[id] = ack
	c.queueControlFrame(func(fr *http2.Framer) error { return fr.WritePing(false, id) })
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pings, id)
		c.mu.Unlock()
	}()
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.done:
		return c.failure()
	}
}

// Close closes the underlying connection, which ends the proxied connection.
func (c *HTTP2ClientConn) Close() error {
	c.fail(net.ErrClosed)
	return nil
}

func (c *HTTP2ClientConn) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *HTTP2ClientConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		close(c.done)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	c.nc.Close()
}

// failWrite ends the connection after a failed write, and returns its error.
// A peer closing the connection breaks writes, and what it sent before closing
// tells why, like the TLS alert refusing a client certificate, which arrives
// after the handshake: the read loop gets to report that first.
func (c *HTTP2ClientConn) failWrite(err error) error {
	timer := time.NewTimer(http2WriteFailureGrace)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
	}
	c.fail(fmt.Errorf("connect-ip: writing to the proxy: %w", err))
	return c.failure()
}

func (c *HTTP2ClientConn) queueControlFrame(write func(*http2.Framer) error) {
	c.control = append(c.control, write)
	c.cond.Broadcast()
}

func (c *HTTP2ClientConn) writeFrame(write func(*http2.Framer) error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return write(c.fr)
}

func (c *HTTP2ClientConn) writeControlFrames() {
	for {
		c.mu.Lock()
		for len(c.control) == 0 && c.err == nil {
			c.cond.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		write := c.control[0]
		c.control[0] = nil
		c.control = c.control[1:]
		c.mu.Unlock()

		if err := c.writeFrame(write); err != nil {
			c.failWrite(err)
			return
		}
	}
}

func (c *HTTP2ClientConn) readFrames() {
	for first := true; ; first = false {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.fail(fmt.Errorf("connect-ip: reading from the proxy: %w", err))
			return
		}
		if settings, ok := f.(*http2.SettingsFrame); first && (!ok || settings.IsAck()) {
			c.fail(fmt.Errorf("connect-ip: expected a SETTINGS frame from the proxy, got %s", f.Header().Type))
			return
		}
		if err := c.handleFrame(f); err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *HTTP2ClientConn) handleFrame(f http2.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch f := f.(type) {
	case *http2.SettingsFrame:
		return c.handleSettings(f)
	case *http2.MetaHeadersFrame:
		return c.handleHeaders(f)
	case *http2.DataFrame:
		return c.handleData(f)
	case *http2.WindowUpdateFrame:
		return c.handleWindowUpdate(f)
	case *http2.PingFrame:
		return c.handlePing(f)
	case *http2.RSTStreamFrame:
		return c.handleReset(f)
	case *http2.GoAwayFrame:
		// The proxy can drain its connections: the stream it didn't reject goes on until it ends.
		if f.ErrCode != http2.ErrCodeNo || f.LastStreamID < http2StreamID {
			return fmt.Errorf("connect-ip: GOAWAY from the proxy: %s", f.ErrCode)
		}
	case *http2.PushPromiseFrame:
		return errors.New("connect-ip: PUSH_PROMISE from the proxy, although disabled")
	}
	return nil
}

func (c *HTTP2ClientConn) checkControlQueue() error {
	if len(c.control) >= maxQueuedHTTP2ControlFrames {
		return errors.New("connect-ip: the proxy doesn't read its control frames")
	}
	return nil
}

func (c *HTTP2ClientConn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	if err := c.checkControlQueue(); err != nil {
		return err
	}
	err := f.ForeachSetting(func(s http2.Setting) error {
		if err := s.Valid(); err != nil {
			return fmt.Errorf("connect-ip: invalid setting from the proxy %s: %w", s, err)
		}
		switch s.ID {
		case http2.SettingInitialWindowSize:
			// RFC 9113, section 6.9.2: this applies to the stream, and can make its window negative.
			c.streamSend += int64(s.Val) - c.initialSend
			c.initialSend = int64(s.Val)
		case http2.SettingMaxFrameSize:
			c.maxFrame = int64(s.Val)
		case http2.SettingEnableConnectProtocol:
			c.extendedConnect = s.Val == 1
		case http2.SettingMaxConcurrentStreams:
			c.noStreams = s.Val == 0
		}
		return nil
	})
	if err != nil {
		return err
	}
	if c.streamSend > http2MaxWindow {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	c.queueControlFrame(func(fr *http2.Framer) error { return fr.WriteSettingsAck() })
	if !c.sawSettings {
		c.sawSettings = true
		close(c.settings)
	}
	return nil
}

func (c *HTTP2ClientConn) handleHeaders(f *http2.MetaHeadersFrame) error {
	if f.StreamID != http2StreamID || !c.dialed {
		return fmt.Errorf("connect-ip: unexpected HEADERS from the proxy on stream %d", f.StreamID)
	}
	if f.Truncated {
		return errors.New("connect-ip: response headers too large")
	}
	if c.recvEnded {
		return http2.ConnectionError(http2.ErrCodeStreamClosed)
	}
	if c.responded {
		// Trailers, which end the stream and carry no pseudo-header: RFC 9113, section 8.1.
		if !f.StreamEnded() || len(f.PseudoFields()) > 0 {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		c.recvEnded = true
		c.cond.Broadcast()
		return nil
	}
	status, err := parseHTTP2Status(f.PseudoValue("status"))
	if err != nil {
		return err
	}
	if status >= 100 && status <= 199 {
		// An interim response that ends the stream is malformed: RFC 9113, section 8.1.
		// Dial would otherwise wait for a final response that can't come.
		if f.StreamEnded() {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		return nil
	}
	if f.StreamEnded() {
		c.recvEnded = true
		c.cond.Broadcast()
	}
	header := make(http.Header)
	for _, field := range f.RegularFields() {
		header.Add(field.Name, field.Value)
	}
	c.responded = true
	c.response <- &http.Response{
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode: status,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		Body:       http.NoBody,
	}
	return nil
}

// parseHTTP2Status parses a :status pseudo-header, which RFC 9113, section 8.3.2 makes a 3-digit code.
func parseHTTP2Status(s string) (int, error) {
	if len(s) != 3 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("connect-ip: invalid status from the proxy: %q", s)
	}
	return strconv.Atoi(s)
}

func (c *HTTP2ClientConn) handleData(f *http2.DataFrame) error {
	if f.StreamID != http2StreamID || !c.responded {
		return fmt.Errorf("connect-ip: unexpected DATA from the proxy on stream %d", f.StreamID)
	}
	if c.recvEnded {
		return http2.ConnectionError(http2.ErrCodeStreamClosed)
	}
	// Flow control covers the whole frame, padding included.
	size := int64(f.Length)
	c.recvUsed += size
	if c.recvUsed > c.window {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	if c.recvClosed {
		c.consume(size)
	} else {
		data := f.Data()
		c.recv.Write(data)
		c.consume(size - int64(len(data)))
	}
	if f.StreamEnded() {
		c.recvEnded = true
	}
	c.cond.Broadcast()
	return nil
}

// consume returns n bytes of flow control credit to the proxy.
// It batches them, so that a stream of small frames doesn't cause as many WINDOW_UPDATE frames,
// and queues a single WINDOW_UPDATE at a time, which takes the credit accrued while it waited.
// The window only widens when the writer takes the credit: a proxy that sends more than
// it was credited exceeds the window, and can't make the control queue grow.
func (c *HTTP2ClientConn) consume(n int64) {
	c.recvCredit += n
	if c.creditQueued || c.recvCredit < c.window/2 {
		return
	}
	c.creditQueued = true
	c.queueControlFrame(c.writeWindowUpdate)
}

// writeWindowUpdate credits the proxy with what was consumed, on both the connection and the stream.
func (c *HTTP2ClientConn) writeWindowUpdate(fr *http2.Framer) error {
	c.mu.Lock()
	credit := uint32(c.recvCredit)
	c.recvUsed -= c.recvCredit
	c.recvCredit = 0
	c.creditQueued = false
	c.mu.Unlock()
	if err := fr.WriteWindowUpdate(0, credit); err != nil {
		return err
	}
	return fr.WriteWindowUpdate(http2StreamID, credit)
}

func (c *HTTP2ClientConn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	window := &c.streamSend
	if f.StreamID == 0 {
		window = &c.connSend
	} else if f.StreamID != http2StreamID || !c.dialed {
		// RFC 9113, section 5.1: a frame on an idle stream is a connection error.
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	*window += int64(f.Increment)
	if *window > http2MaxWindow {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	c.cond.Broadcast()
	return nil
}

func (c *HTTP2ClientConn) handlePing(f *http2.PingFrame) error {
	if f.IsAck() {
		if ack, ok := c.pings[f.Data]; ok {
			close(ack)
			delete(c.pings, f.Data)
		}
		return nil
	}
	if err := c.checkControlQueue(); err != nil {
		return err
	}
	data := f.Data
	c.queueControlFrame(func(fr *http2.Framer) error { return fr.WritePing(true, data) })
	return nil
}

func (c *HTTP2ClientConn) handleReset(f *http2.RSTStreamFrame) error {
	if f.StreamID != http2StreamID || !c.dialed {
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	// A server that finished its response can tell the client not to bother
	// sending the rest of the request. This isn't an error: RFC 9113, section 8.1.
	if !c.recvEnded || f.ErrCode != http2.ErrCodeNo {
		return fmt.Errorf("connect-ip: stream reset by the proxy: %s", f.ErrCode)
	}
	c.sendClosed = true
	c.cond.Broadcast()
	return nil
}

func (c *HTTP2ClientConn) reset(code http2.ErrCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resetSent {
		return
	}
	c.resetSent = true
	c.sendClosed = true
	if c.writing {
		// The RST_STREAM would wait behind a DATA frame that the network doesn't
		// take: a proxy that stopped reading. Interrupting that write breaks the
		// framing, so it ends the connection, which this stream was the only use of.
		_ = c.nc.SetWriteDeadline(time.Now())
	}
	c.queueControlFrame(func(fr *http2.Framer) error { return fr.WriteRSTStream(http2StreamID, code) })
}

// reserve waits for flow control to allow sending a frame of up to size bytes, and returns its size.
func (c *HTTP2ClientConn) reserve(size int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		switch {
		case c.err != nil:
			return 0, c.err
		case c.sendClosed:
			return 0, net.ErrClosed
		case c.connSend > 0 && c.streamSend > 0:
			n := min(int64(size), c.connSend, c.streamSend, c.maxFrame)
			c.connSend -= n
			c.streamSend -= n
			return int(n), nil
		}
		c.cond.Wait()
	}
}

// clientBody is the client's end of the HTTP/2 stream of an HTTP2ClientConn.
type clientBody struct {
	c *HTTP2ClientConn
}

var _ http2Body = &clientBody{}

func (b *clientBody) Read(p []byte) (int, error) {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.recv.Len() == 0 {
		switch {
		case c.recvClosed:
			return 0, net.ErrClosed
		case c.recvEnded:
			return 0, io.EOF
		case c.err != nil:
			return 0, c.err
		}
		c.cond.Wait()
	}
	n, _ := c.recv.Read(p)
	c.consume(int64(n))
	return n, nil
}

func (b *clientBody) Write(p []byte) (int, error) {
	c := b.c
	var written int
	for written < len(p) {
		n, err := c.reserve(len(p) - written)
		if err != nil {
			return written, err
		}
		sent, err := c.writeData(p[written : written+n])
		written += sent
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// writeData sends frame, which flow control allowed, in DATA frames, and returns how much it sent.
func (c *HTTP2ClientConn) writeData(frame []byte) (int, error) {
	// Under the same lock as reset, which interrupts a DATA write only if it sees it.
	c.mu.Lock()
	if err := c.err; err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if c.sendClosed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.writing = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.writing = false
		c.mu.Unlock()
	}()

	var sent int
	err := c.writeFrame(func(fr *http2.Framer) error {
		// The proxy may have changed its settings since the reservation, and the SETTINGS ACK
		// gone out first: then the proxy applies them to these frames. Both writes hold wmu,
		// so the settings read here include all the acknowledged ones.
		c.mu.Lock()
		if c.streamSend < 0 {
			// A lower SETTINGS_INITIAL_WINDOW_SIZE took back part of the reservation.
			excess := min(int64(len(frame)), -c.streamSend)
			c.streamSend += excess
			c.connSend += excess
			frame = frame[:int64(len(frame))-excess]
		}
		c.mu.Unlock()
		for len(frame) > 0 {
			c.mu.Lock()
			n := min(len(frame), int(c.maxFrame))
			c.mu.Unlock()
			if err := fr.WriteData(http2StreamID, false, frame[:n]); err != nil {
				return err
			}
			frame = frame[n:]
			sent += n
		}
		return nil
	})
	if err != nil {
		return sent, c.failWrite(err)
	}
	return sent, nil
}

func (b *clientBody) CloseWrite() error {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendClosed {
		return nil
	}
	c.sendClosed = true
	c.queueControlFrame(func(fr *http2.Framer) error { return fr.WriteData(http2StreamID, true, nil) })
	return nil
}

func (b *clientBody) CloseRead() {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recvClosed = true
	c.consume(int64(c.recv.Len()))
	c.recv.Reset()
	c.cond.Broadcast()
}

func (b *clientBody) Reset(code http2.ErrCode) { b.c.reset(code) }
