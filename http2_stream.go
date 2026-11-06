package connectip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/http2"
)

// capsuleTypeDatagram is the DATAGRAM capsule of RFC 9297, section 3.5.
const capsuleTypeDatagram http3.CapsuleType = 0

const (
	// maxHTTP2Datagram fits the largest IPv6 packet without a jumbo payload, and a Context ID.
	maxHTTP2Datagram = 40 + 65535 + 1
	// maxQueuedHTTP2Datagrams bounds the datagrams waiting for ReadPacket.
	maxQueuedHTTP2Datagrams = 128
	// maxPendingHTTP2Bytes bounds the capsules waiting for the stream to accept them.
	// The stream is ordered and reliable, so a longer queue would only add latency.
	maxPendingHTTP2Bytes = 128 << 10
	// http2CloseTimeout bounds how long closing a stream waits for pending capsules.
	http2CloseTimeout = time.Second
)

// http2Body is one end of an HTTP/2 stream.
type http2Body interface {
	io.Reader
	// Write returns once p was sent, which flow control can delay for as long as the peer wants.
	Write(p []byte) (int, error)
	// CloseWrite ends the send side.
	CloseWrite() error
	// CloseRead makes Read fail, and drops what the peer still sends.
	CloseRead()
	// Reset aborts the stream, which fails a Write in progress.
	Reset(http2.ErrCode)
}

// http2Stream gives an HTTP/2 stream the datagrams of an HTTP/3 one.
// RFC 9297 carries them as DATAGRAM capsules, between the other capsules of the stream:
// Read takes them out and SendDatagram puts them in, so that Conn doesn't see the difference.
//
// As on HTTP/3, datagrams may be lost. SendDatagram never waits for the stream, which
// could take arbitrarily long: when the path is saturated, it drops the packet instead,
// and the congestion control of the tunneled connections reacts as on a congested link.
type http2Stream struct {
	body http2Body

	r             *bufio.Reader
	capsuleHeader []byte // the header of the current capsule, not yet returned by Read
	capsuleLeft   int64  // the payload of the current capsule, not yet returned by Read
	datagrams     chan []byte

	mu          sync.Mutex
	cond        sync.Cond
	pending     []byte // complete capsules, in the order they were queued
	closed      bool
	interrupted bool
	err         error
	flushed     chan struct{} // closed when flush returns
}

var _ http3Stream = &http2Stream{}

func newHTTP2Stream(body http2Body) *http2Stream {
	s := &http2Stream{
		body:      body,
		r:         bufio.NewReader(body),
		datagrams: make(chan []byte, maxQueuedHTTP2Datagrams),
		flushed:   make(chan struct{}),
	}
	s.cond.L = &s.mu
	go s.flush()
	return s
}

// Read returns the bytes of the stream, without the DATAGRAM capsules.
func (s *http2Stream) Read(p []byte) (int, error) {
	for len(s.capsuleHeader) == 0 && s.capsuleLeft == 0 {
		if err := s.nextCapsule(); err != nil {
			return 0, err
		}
	}
	if len(s.capsuleHeader) > 0 {
		n := copy(p, s.capsuleHeader)
		s.capsuleHeader = s.capsuleHeader[n:]
		return n, nil
	}
	if int64(len(p)) > s.capsuleLeft {
		p = p[:s.capsuleLeft]
	}
	n, err := s.r.Read(p)
	s.capsuleLeft -= int64(n)
	return n, err
}

func (s *http2Stream) nextCapsule() error {
	typ, err := quicvarint.Read(s.r)
	if err != nil {
		return err
	}
	length, err := quicvarint.Read(s.r)
	if err != nil {
		return truncatedCapsule(err)
	}
	if http3.CapsuleType(typ) != capsuleTypeDatagram {
		s.capsuleHeader = quicvarint.Append(quicvarint.Append(nil, typ), length)
		s.capsuleLeft = int64(length)
		return nil
	}
	if length > maxHTTP2Datagram {
		_, err := io.CopyN(io.Discard, s.r, int64(length))
		return truncatedCapsule(err)
	}
	datagram := make([]byte, length)
	if _, err := io.ReadFull(s.r, datagram); err != nil {
		return truncatedCapsule(err)
	}
	select {
	case s.datagrams <- datagram:
	default:
	}
	return nil
}

func truncatedCapsule(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// ReceiveDatagram returns the next DATAGRAM capsule. Read needs to be running.
func (s *http2Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case datagram := <-s.datagrams:
		return datagram, nil
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}
}

// SendDatagram queues a DATAGRAM capsule, or drops it if the queue is full.
func (s *http2Stream) SendDatagram(data []byte) error {
	if len(data) > maxHTTP2Datagram {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: maxHTTP2Datagram}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeErr(); err != nil {
		return err
	}
	if len(s.pending) >= maxPendingHTTP2Bytes {
		return nil
	}
	s.pending = quicvarint.Append(s.pending, uint64(capsuleTypeDatagram))
	s.pending = quicvarint.Append(s.pending, uint64(len(data)))
	s.pending = append(s.pending, data...)
	s.cond.Broadcast()
	return nil
}

// Write queues capsules. Conn writes one complete capsule per call, so that DATAGRAM
// capsules can't end up in the middle of one. Unlike those, these capsules can't be lost.
func (s *http2Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.writeErr() == nil && !s.interrupted && len(s.pending) >= maxPendingHTTP2Bytes {
		s.cond.Wait()
	}
	if err := s.writeErr(); err != nil {
		return 0, err
	}
	if len(s.pending) >= maxPendingHTTP2Bytes {
		return 0, os.ErrDeadlineExceeded
	}
	s.pending = append(s.pending, p...)
	s.cond.Broadcast()
	return len(p), nil
}

func (s *http2Stream) writeErr() error {
	if s.err != nil {
		return s.err
	}
	if s.closed {
		return net.ErrClosed
	}
	return nil
}

func (s *http2Stream) flush() {
	defer close(s.flushed)

	var batch []byte
	for {
		s.mu.Lock()
		for len(s.pending) == 0 && !s.closed {
			s.cond.Wait()
		}
		if len(s.pending) == 0 {
			s.mu.Unlock()
			return
		}
		s.pending, batch = batch[:0], s.pending
		s.cond.Broadcast()
		s.mu.Unlock()

		if _, err := s.body.Write(batch); err != nil {
			s.mu.Lock()
			s.err = err
			s.pending = nil
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
	}
}

// SetWriteDeadline interrupts a Write that is waiting for the queue to drain.
// Conn only calls this with the current time to shut down, so it doesn't look at the time.
func (s *http2Stream) SetWriteDeadline(time.Time) error {
	s.mu.Lock()
	s.interrupted = true
	s.cond.Broadcast()
	s.mu.Unlock()
	return nil
}

// Close sends the queued capsules and ends the send side.
// It aborts the stream if the peer's flow control doesn't let them out.
func (s *http2Stream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()

	timer := time.NewTimer(http2CloseTimeout)
	defer timer.Stop()
	select {
	case <-s.flushed:
		return s.body.CloseWrite()
	case <-timer.C:
		s.body.Reset(http2.ErrCodeCancel)
		return fmt.Errorf("connect-ip: closing the stream: %w", os.ErrDeadlineExceeded)
	}
}

func (s *http2Stream) CancelRead(quic.StreamErrorCode) { s.body.CloseRead() }

func (s *http2Stream) CancelWrite(code quic.StreamErrorCode) {
	s.mu.Lock()
	s.closed = true
	s.pending = nil
	s.cond.Broadcast()
	s.mu.Unlock()
	s.body.Reset(http2ErrCode(code))
}

func http2ErrCode(code quic.StreamErrorCode) http2.ErrCode {
	switch http3.ErrCode(code) {
	case http3.ErrCodeNoError:
		return http2.ErrCodeNo
	case http3.ErrCodeExcessiveLoad:
		return http2.ErrCodeEnhanceYourCalm
	default:
		return http2.ErrCodeCancel
	}
}

// StreamID is only used for qlog, which isn't available on HTTP/2.
func (s *http2Stream) StreamID() quic.StreamID { return 0 }

// QlogTrace returns nil: qlog describes the events of a QUIC connection.
func (s *http2Stream) QlogTrace() qlogwriter.Trace { return nil }

// proxyHTTP2 answers an extended CONNECT request on a net/http server.
func proxyHTTP2(w http.ResponseWriter, body io.ReadCloser) (*Conn, error) {
	rc := http.NewResponseController(w)
	// A proxied connection outlives the timeouts that a server applies to requests.
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return nil, fmt.Errorf("connect-ip: failed to send response: %w", err)
	}
	return newProxiedConn(newHTTP2Stream(&proxyBody{w: w, rc: rc, body: body}), nil), nil
}

// proxyBody is the proxy's end of an HTTP/2 stream.
// It stops using the ResponseWriter on CloseWrite and Reset, since
// a net/http handler is free to return as soon as the Conn is closed.
type proxyBody struct {
	w    http.ResponseWriter
	rc   *http.ResponseController
	body io.ReadCloser

	mu     sync.Mutex // held during a Write
	closed atomic.Bool
}

func (b *proxyBody) Read(p []byte) (int, error) { return b.body.Read(p) }

func (b *proxyBody) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := b.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, b.rc.Flush()
}

// CloseWrite doesn't send anything: net/http ends the stream when the handler returns.
func (b *proxyBody) CloseWrite() error {
	b.closed.Store(true)
	return nil
}

func (b *proxyBody) CloseRead() { b.body.Close() }

// Reset relies on net/http resetting the stream, with INTERNAL_ERROR,
// when a write deadline passes: there's no other way for a handler to do so.
func (b *proxyBody) Reset(http2.ErrCode) {
	if b.closed.Load() {
		return
	}
	_ = b.rc.SetWriteDeadline(time.Unix(1, 0))
	// The lock waits for a Write in progress, which the reset just failed.
	b.mu.Lock()
	b.closed.Store(true)
	b.mu.Unlock()
}
