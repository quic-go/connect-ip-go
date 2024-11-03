package main

import (
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
