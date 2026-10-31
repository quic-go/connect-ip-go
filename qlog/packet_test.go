package qlog

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func checkPacket(t *testing.T, p Packet, expected string) {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, p.encode(jsontext.NewEncoder(&buf)))
	require.JSONEq(t, expected, buf.String())
}

func TestIPv4Packet(t *testing.T) {
	checkPacket(t, Packet{
		Header: IPv4Header{
			TotalLength:        28,
			TTL:                64,
			Protocol:           1,
			SourceAddress:      netip.MustParseAddr("192.0.2.1"),
			DestinationAddress: netip.MustParseAddr("198.51.100.1"),
		},
		ICMP: &ICMP{Type: 8}, // Echo Request
		Raw:  RawInfo{Length: 28, PayloadLength: 8},
	}, `{
		"header": {
			"version": 4,
			"total_length": 28,
			"ttl": 64,
			"protocol": 1,
			"source_address": "192.0.2.1",
			"destination_address": "198.51.100.1"
		},
		"icmp": {"type": 8, "code": 0},
		"raw": {"length": 28, "payload_length": 8}
	}`)
}

func TestPacketWithoutHeader(t *testing.T) {
	checkPacket(t, Packet{Raw: RawInfo{Length: 3, PayloadLength: OmitLength}}, `{"raw": {"length": 3}}`)
}
