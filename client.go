package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// A ClientConn represents a connection to a single proxy server.
// Multiple proxied connections can be established over a single ClientConn.
type ClientConn struct {
	clientConn *http3.ClientConn
}

// NewClientConn creates a client connection using an existing HTTP/3 connection.
// The HTTP/3 connection and its underlying QUIC connection must have datagrams enabled.
// The caller owns the HTTP/3 connection and can also use it for ordinary HTTP requests.
// Closing a [Conn] returned by [ClientConn.Dial] does not close the HTTP/3 connection.
func NewClientConn(conn *http3.ClientConn) *ClientConn {
	return &ClientConn{clientConn: conn}
}

// Dial dials a proxied connection over the proxy connection.
func (c *ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	return c.dial(req, nil)
}

func (c *ClientConn) dial(req *Request, closeConn func() error) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}

	select {
	case <-httpReq.Context().Done():
		return nil, nil, context.Cause(httpReq.Context())
	case <-c.clientConn.Context().Done():
		return nil, nil, context.Cause(c.clientConn.Context())
	case <-c.clientConn.ReceivedSettings():
	}

	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		return nil, nil, errors.New("connect-ip: server didn't enable datagrams")
	}

	rstr, err := c.clientConn.OpenRequestStream(httpReq.Context())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	var keepStream bool
	defer func() {
		if !keepStream {
			rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			rstr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	if err := rstr.SendRequestHeader(httpReq); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	// TODO: optimistically return the connection
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	keepStream = true
	return newProxiedConn(rstr, closeConn), rsp, nil
}
