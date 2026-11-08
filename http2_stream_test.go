package connectip

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// fakeHTTP2Body records what an http2Stream does. Its writes block while gate is set.
type fakeHTTP2Body struct {
	io.Reader

	gate chan struct{} // closed to let the writes through

	mu         sync.Mutex
	written    []byte
	writeErr   error
	closeWrite bool
	closeRead  bool
	reset      []http2.ErrCode
	reseted    chan struct{}
}

func newFakeHTTP2Body(r io.Reader) *fakeHTTP2Body {
	if r == nil {
		r = blockingReader{}
	}
	return &fakeHTTP2Body{Reader: r, reseted: make(chan struct{})}
}

type blockingReader struct{}

func (blockingReader) Read([]byte) (int, error) { select {} }

func (b *fakeHTTP2Body) Write(p []byte) (int, error) {
	if b.gate != nil {
		select {
		case <-b.gate:
		case <-b.reseted:
			return 0, errors.New("stream reset")
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	b.written = append(b.written, p...)
	return len(p), nil
}

func (b *fakeHTTP2Body) CloseWrite() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeWrite = true
	return nil
}

func (b *fakeHTTP2Body) CloseRead() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeRead = true
}

func (b *fakeHTTP2Body) Reset(code http2.ErrCode) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reset = append(b.reset, code)
	if len(b.reset) == 1 {
		close(b.reseted)
	}
}

func (b *fakeHTTP2Body) writtenBytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.written)
}

func appendTestCapsule(b []byte, typ http3.CapsuleType, payload string) []byte {
	b = quicvarint.Append(b, uint64(typ))
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func TestHTTP2StreamSeparatesDatagrams(t *testing.T) {
	var input, want []byte
	input = appendTestCapsule(input, capsuleTypeRouteAdvertisement, "route")
	input = appendTestCapsule(input, capsuleTypeDatagram, "first")
	input = appendTestCapsule(input, capsuleTypeAddressAssign, "")
	input = appendTestCapsule(input, capsuleTypeDatagram, "")
	input = appendTestCapsule(input, capsuleTypeDatagram, "second")
	input = appendTestCapsule(input, 0x41, "unknown")
	want = appendTestCapsule(want, capsuleTypeRouteAdvertisement, "route")
	want = appendTestCapsule(want, capsuleTypeAddressAssign, "")
	want = appendTestCapsule(want, 0x41, "unknown")

	for name, r := range map[string]io.Reader{
		"complete":      bytes.NewReader(input),
		"byte by byte":  iotest.OneByteReader(bytes.NewReader(input)),
		"with the data": iotest.DataErrReader(bytes.NewReader(input)),
	} {
		t.Run(name, func(t *testing.T) {
			s := newHTTP2Stream(newFakeHTTP2Body(r))
			defer s.CancelWrite(0)
			got, err := io.ReadAll(s)
			require.NoError(t, err)
			require.Equal(t, want, got)

			for _, datagram := range []string{"first", "", "second"} {
				got, err := s.ReceiveDatagram(t.Context())
				require.NoError(t, err)
				require.Equal(t, datagram, string(got))
			}
		})
	}
}

func TestHTTP2StreamTruncatedCapsule(t *testing.T) {
	datagram := appendTestCapsule(nil, capsuleTypeDatagram, "datagram")
	for name, input := range map[string][]byte{
		"length":           datagram[:1],
		"datagram payload": datagram[:len(datagram)-1],
	} {
		t.Run(name, func(t *testing.T) {
			s := newHTTP2Stream(newFakeHTTP2Body(bytes.NewReader(input)))
			defer s.CancelWrite(0)
			_, err := io.ReadAll(s)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

func TestHTTP2StreamDropsOversizedDatagrams(t *testing.T) {
	input := appendTestCapsule(nil, capsuleTypeDatagram, string(make([]byte, maxHTTP2Datagram+1)))
	input = appendTestCapsule(input, capsuleTypeAddressAssign, "address")

	s := newHTTP2Stream(newFakeHTTP2Body(bytes.NewReader(input)))
	defer s.CancelWrite(0)
	got, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, appendTestCapsule(nil, capsuleTypeAddressAssign, "address"), got)
	require.Empty(t, s.datagrams)
}

func TestHTTP2StreamDropsDatagramsNobodyReads(t *testing.T) {
	var input []byte
	for range maxQueuedHTTP2Datagrams + 1 {
		input = appendTestCapsule(input, capsuleTypeDatagram, "datagram")
	}
	input = appendTestCapsule(input, capsuleTypeAddressAssign, "address")

	s := newHTTP2Stream(newFakeHTTP2Body(bytes.NewReader(input)))
	defer s.CancelWrite(0)
	got, err := io.ReadAll(s)
	require.NoError(t, err)
	require.Equal(t, appendTestCapsule(nil, capsuleTypeAddressAssign, "address"), got)
	require.Len(t, s.datagrams, maxQueuedHTTP2Datagrams)
}

func TestHTTP2StreamReceiveDatagramCanceled(t *testing.T) {
	s := newHTTP2Stream(newFakeHTTP2Body(nil))
	defer s.CancelWrite(0)
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(net.ErrClosed)
	_, err := s.ReceiveDatagram(ctx)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestHTTP2StreamSendsCapsules(t *testing.T) {
	body := newFakeHTTP2Body(nil)
	s := newHTTP2Stream(body)
	require.NoError(t, s.SendDatagram([]byte("first")))
	control := appendTestCapsule(nil, capsuleTypeAddressAssign, "address")
	n, err := s.Write(control)
	require.NoError(t, err)
	require.Equal(t, len(control), n)
	require.NoError(t, s.SendDatagram([]byte("second")))
	require.NoError(t, s.Close())

	var want []byte
	want = appendTestCapsule(want, capsuleTypeDatagram, "first")
	want = append(want, control...)
	want = appendTestCapsule(want, capsuleTypeDatagram, "second")
	require.Equal(t, want, body.writtenBytes())
	require.True(t, body.closeWrite)
	require.Empty(t, body.reset)
}

func TestHTTP2StreamSendDatagramDoesNotWait(t *testing.T) {
	body := newFakeHTTP2Body(nil)
	body.gate = make(chan struct{})
	s := newHTTP2Stream(body)

	payload := make([]byte, 1400)
	// The flush loop holds one full queue, and the stream keeps another one.
	const sent = 4 * maxPendingHTTP2Bytes / 1400
	for range sent {
		require.NoError(t, s.SendDatagram(payload))
	}
	close(body.gate)
	require.NoError(t, s.Close())

	r := http3.NewCapsuleParser(bytes.NewReader(body.writtenBytes()))
	var capsules int
	for {
		typ, cr, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		require.Equal(t, capsuleTypeDatagram, typ)
		got, err := io.ReadAll(cr)
		require.NoError(t, err)
		require.Len(t, got, len(payload))
		capsules++
	}
	require.NotZero(t, capsules)
	require.Less(t, capsules, sent)
	// Every datagram was either sent or counted.
	require.EqualValues(t, sent-capsules, s.dropped.Load())
}

func TestHTTP2ConnCountsDroppedDatagrams(t *testing.T) {
	require.Zero(t, newProxiedConn(&mockStream{}, nil).DroppedDatagrams())

	body := newFakeHTTP2Body(nil)
	body.gate = make(chan struct{})
	s := newHTTP2Stream(body)
	conn := newProxiedConn(s, nil)
	fillHTTP2Stream(t, s)
	dropped := conn.DroppedDatagrams()
	require.NoError(t, s.SendDatagram(nil))
	require.Equal(t, dropped+1, conn.DroppedDatagrams())

	close(body.gate)
	require.NoError(t, conn.Close())
	require.Equal(t, dropped+1, conn.DroppedDatagrams())
}

func TestHTTP2StreamTooLargeDatagram(t *testing.T) {
	s := newHTTP2Stream(newFakeHTTP2Body(nil))
	defer s.CancelWrite(0)
	require.NoError(t, s.SendDatagram(make([]byte, maxHTTP2Datagram)))
	err := s.SendDatagram(make([]byte, maxHTTP2Datagram+1))
	var tooLarge *quic.DatagramTooLargeError
	require.ErrorAs(t, err, &tooLarge)
	require.EqualValues(t, maxHTTP2Datagram, tooLarge.MaxDatagramPayloadSize)
}

// fillHTTP2Stream blocks the flush loop on a first batch, and fills the queue behind it.
func fillHTTP2Stream(t *testing.T, s *http2Stream) {
	t.Helper()
	require.NoError(t, s.SendDatagram(nil))
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return len(s.pending) == 0
	}, time.Second, time.Millisecond)
	for range maxPendingHTTP2Bytes/1024 + 1 {
		require.NoError(t, s.SendDatagram(make([]byte, 1024)))
	}
}

func TestHTTP2StreamWriteWaitsForRoom(t *testing.T) {
	body := newFakeHTTP2Body(nil)
	body.gate = make(chan struct{})
	s := newHTTP2Stream(body)
	fillHTTP2Stream(t, s)

	control := appendTestCapsule(nil, capsuleTypeAddressAssign, "address")
	done := make(chan error, 1)
	go func() {
		_, err := s.Write(control)
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("Write didn't wait")
	case <-time.After(10 * time.Millisecond):
	}
	close(body.gate)
	require.NoError(t, <-done)
	require.NoError(t, s.Close())
	require.True(t, bytes.HasSuffix(body.writtenBytes(), control))
}

func TestHTTP2StreamWriteInterrupted(t *testing.T) {
	body := newFakeHTTP2Body(nil)
	body.gate = make(chan struct{})
	s := newHTTP2Stream(body)
	defer s.CancelWrite(0)
	fillHTTP2Stream(t, s)

	done := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("capsule"))
		done <- err
	}()
	require.NoError(t, s.SetWriteDeadline(time.Now()))
	require.ErrorIs(t, <-done, os.ErrDeadlineExceeded)
}

func TestHTTP2StreamCloseTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		body := newFakeHTTP2Body(nil)
		body.gate = make(chan struct{})
		s := newHTTP2Stream(body)
		require.NoError(t, s.SendDatagram(nil))

		start := time.Now()
		require.ErrorIs(t, s.Close(), os.ErrDeadlineExceeded)
		require.Equal(t, http2CloseTimeout, time.Since(start))
		require.Equal(t, []http2.ErrCode{http2.ErrCodeCancel}, body.reset)
		require.False(t, body.closeWrite)
		synctest.Wait()
	})
}

func TestHTTP2StreamCancelWrite(t *testing.T) {
	for name, tc := range map[string]struct {
		code quic.StreamErrorCode
		want http2.ErrCode
	}{
		"no error":      {quic.StreamErrorCode(http3.ErrCodeNoError), http2.ErrCodeNo},
		"excessive":     {quic.StreamErrorCode(http3.ErrCodeExcessiveLoad), http2.ErrCodeEnhanceYourCalm},
		"anything else": {quic.StreamErrorCode(http3.ErrCodeInternalError), http2.ErrCodeCancel},
	} {
		t.Run(name, func(t *testing.T) {
			body := newFakeHTTP2Body(nil)
			body.gate = make(chan struct{})
			s := newHTTP2Stream(body)
			require.NoError(t, s.SendDatagram(nil))

			s.CancelWrite(tc.code)
			require.Equal(t, []http2.ErrCode{tc.want}, body.reset)
			<-s.flushed
			require.Error(t, s.SendDatagram(nil))
			_, err := s.Write([]byte("capsule"))
			require.Error(t, err)
		})
	}
}

func TestHTTP2StreamCancelRead(t *testing.T) {
	body := newFakeHTTP2Body(nil)
	s := newHTTP2Stream(body)
	defer s.CancelWrite(0)
	s.CancelRead(0)
	require.True(t, body.closeRead)
}

func TestHTTP2StreamWriteFailure(t *testing.T) {
	writeErr := errors.New("write failed")
	body := newFakeHTTP2Body(nil)
	body.writeErr = writeErr
	s := newHTTP2Stream(body)
	require.NoError(t, s.SendDatagram(nil))
	<-s.flushed
	require.ErrorIs(t, s.SendDatagram(nil), writeErr)
	_, err := s.Write([]byte("capsule"))
	require.ErrorIs(t, err, writeErr)
}

func TestHTTP2ConnOverStream(t *testing.T) {
	// The stream reports the end of the data, and Conn turns it into a remote close.
	body := newFakeHTTP2Body(bytes.NewReader(nil))
	conn := newProxiedConn(newHTTP2Stream(body), nil)
	_, err := conn.ReadPacket(make([]byte, 1500))
	var closeErr *CloseError
	require.ErrorAs(t, err, &closeErr)
	require.True(t, closeErr.Remote)
	require.NoError(t, conn.Close())
	require.True(t, body.closeRead)
}

type responseWriterWithoutFlush struct{ http.ResponseWriter }

func TestProxyHTTP2CannotFlush(t *testing.T) {
	_, err := proxyHTTP2(responseWriterWithoutFlush{httptest.NewRecorder()}, http.NoBody)
	require.ErrorContains(t, err, "failed to send response")
}

func TestProxyBodyStopsAfterClose(t *testing.T) {
	rec := httptest.NewRecorder()
	b := &proxyBody{w: rec, rc: http.NewResponseController(rec), body: http.NoBody}
	n, err := b.Write([]byte("data"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.NoError(t, b.CloseWrite())
	_, err = b.Write([]byte("more"))
	require.ErrorIs(t, err, net.ErrClosed)
	b.Reset(http2.ErrCodeCancel) // must not touch the ResponseWriter after CloseWrite
	require.Equal(t, "data", rec.Body.String())
}
