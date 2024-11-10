package utils

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLastIP(t *testing.T) {
	tests := []struct {
		input    netip.Prefix
		expected netip.Addr
	}{
		{
			netip.MustParsePrefix("10.0.0.0/24"),
			netip.MustParseAddr("10.0.0.255"),
		},
		{
			netip.MustParsePrefix("10.0.0.0/16"),
			netip.MustParseAddr("10.0.255.255"),
		},
		{
			netip.MustParsePrefix("2001:db8::/64"),
			netip.MustParseAddr("2001:db8::ffff:ffff:ffff:ffff"),
		},
		{
			netip.MustParsePrefix("2001:db8::/48"),
			netip.MustParseAddr("2001:db8:0:ffff:ffff:ffff:ffff:ffff"),
		},
		{
			netip.MustParsePrefix("fe80::/10"),
			netip.MustParseAddr("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.input.String(), func(t *testing.T) {
			result := LastIP(tt.input)
			require.Equal(t, tt.expected, result, result.String())
		})
	}
}

func TestPrefixToIPNet(t *testing.T) {
	tests := []struct {
		name   string
		prefix netip.Prefix
	}{
		{
			name:   "IPv4 /24",
			prefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:   "IPv6 /64",
			prefix: netip.MustParsePrefix("2001:db8::/64"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipnet := PrefixToIPNet(tt.prefix)
			// convert back to prefix for comparison
			prefix, err := netip.ParsePrefix(ipnet.String())
			require.NoError(t, err)
			require.Equal(t, tt.prefix, prefix)
		})
	}
}
