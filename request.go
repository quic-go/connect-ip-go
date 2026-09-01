package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

const requestProtocol = "connect-ip"

var capsuleProtocolHeaderValue string

func init() {
	v, err := httpsfv.Marshal(httpsfv.NewItem(true))
	if err != nil {
		panic(fmt.Sprintf("failed to marshal capsule protocol header value: %v", err))
	}
	capsuleProtocolHeaderValue = v
}

// Request is a CONNECT-IP request created by NewRequest.
// The zero value is not valid.
type Request struct {
	req *http.Request
}

// NewRequest creates a CONNECT-IP request.
func NewRequest(ctx context.Context, proxyTemplate *uritemplate.Template) (*Request, error) {
	// connect-ip-go currently does not support IP flow forwarding,
	// see https://github.com/quic-go/connect-ip-go/issues/31.
	if len(proxyTemplate.Varnames()) > 0 {
		return nil, errors.New("connect-ip: IP flow forwarding not supported")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, proxyTemplate.Raw(), nil)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to create request: %w", err)
	}
	req.Proto = requestProtocol
	req.Host = req.URL.Host
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	return &Request{req: req}, nil
}

// Header returns the HTTP header fields sent with the CONNECT-IP request.
// Callers may add custom headers before dialing.
func (r *Request) Header() http.Header { return r.req.Header }

func (r *Request) httpRequest() *http.Request { return r.req }

// ProxyRequest is the parsed CONNECT-IP request returned from ParseProxyRequest.
// It currently doesn't have any fields, since connect-ip-go doesn't support IP flow forwarding.
type ProxyRequest struct{}

// ProxyRequestParseError is returned from ParseProxyRequest if parsing the CONNECT-IP request fails.
// It is recommended that the request is rejected with the corresponding HTTP status code.
type ProxyRequestParseError struct {
	HTTPStatus int
	Err        error
}

func (e *ProxyRequestParseError) Error() string { return e.Err.Error() }
func (e *ProxyRequestParseError) Unwrap() error { return e.Err }

// ParseProxyRequest parses a CONNECT-IP request.
// The template is the URI template that clients will use to configure this proxy.
func ParseProxyRequest(r *http.Request, template *uritemplate.Template) (*ProxyRequest, error) {
	if len(template.Varnames()) > 0 {
		return nil, errors.New("connect-ip-go currently does not support IP flow forwarding")
	}

	u, err := url.Parse(template.Raw())
	if err != nil {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusInternalServerError,
			Err:        fmt.Errorf("failed to parse template: %w", err),
		}
	}
	if r.Method != http.MethodConnect {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusMethodNotAllowed,
			Err:        fmt.Errorf("expected CONNECT request, got %s", r.Method),
		}
	}
	if r.Proto != requestProtocol {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusNotImplemented,
			Err:        fmt.Errorf("unexpected protocol: %s", r.Proto),
		}
	}
	if r.Host != u.Host {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("host in :authority (%s) does not match template host (%s)", r.Host, u.Host),
		}
	}
	capsuleHeaderValues, ok := r.Header[http3.CapsuleProtocolHeader]
	if !ok {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("missing Capsule-Protocol header"),
		}
	}
	item, err := httpsfv.UnmarshalItem(capsuleHeaderValues)
	if err != nil {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("invalid capsule header value: %s", capsuleHeaderValues),
		}
	}
	if v, ok := item.Value.(bool); !ok {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("incorrect capsule header value type: %s", reflect.TypeOf(item.Value)),
		}
	} else if !v {
		return nil, &ProxyRequestParseError{
			HTTPStatus: http.StatusBadRequest,
			Err:        fmt.Errorf("incorrect capsule header value: %t", item.Value),
		}
	}

	return &ProxyRequest{}, nil
}
