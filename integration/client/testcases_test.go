package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPingLocalhost(t *testing.T) {
	localhost := netip.MustParseAddr("127.0.0.1")
	transmitted, received, err := ping(localhost, 100*time.Millisecond, 3)
	require.NoError(t, err)
	require.Equal(t, transmitted, received, "should receive all transmitted packets")
}

func TestHTTPServer(t *testing.T) {
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/hello" {
				fmt.Fprintf(w, "Hello, World!\n")
			}
		}),
	}

	ln, err := net.Listen("tcp", srv.Addr)
	require.NoError(t, err)

	go func() {
		if err := srv.Serve(ln); err != http.ErrServerClosed {
			t.Errorf("unexpected server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		srv.Close()
		ln.Close()
	})

	time.Sleep(100 * time.Millisecond) // give the server a moment to start

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
	require.NoError(t, runHTTPTest(baseURL+"/hello"))
	require.Error(t, runHTTPTest(baseURL+"/not-hello"))
}
