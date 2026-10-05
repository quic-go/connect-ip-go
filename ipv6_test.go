package connectip

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/ipv6"

	"github.com/stretchr/testify/require"
)

// composeIPv6Packet composes an IPv6 packet with a chain of extension headers.
// The arguments are the Next Header values, starting with the one in the IPv6 header.
// All but the last one are extension headers.
func composeIPv6Packet(nextHeaders ...uint8) []byte {
	b := bytes.Clone(ipv6Header)
	b[6] = nextHeaders[0]
	for i, typ := range nextHeaders[:len(nextHeaders)-1] {
		hdr := make([]byte, 16)
		switch typ {
		case ipProtoFragment:
			hdr = hdr[:8]
			hdr[3] = 1 // More Fragments flag
		case ipProtoAH:
			hdr[1] = 2 // in 4-byte units, minus 2
		default:
			hdr[1] = 1 // in 8-byte units, not including the first 8 bytes
		}
		hdr[0] = nextHeaders[i+1]
		b = append(b, hdr...)
	}
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-ipv6.HeaderLen))
	return b
}

func TestIPv6UpperLayerProtocol(t *testing.T) {
	fragment := composeIPv6Packet(ipProtoFragment, 17)
	fragment[ipv6.HeaderLen+2] = 1 // Fragment Offset

	for _, tt := range []struct {
		name        string
		packet      []byte
		want        uint8
		wantPayload []byte
		wantErr     string
	}{
		{
			name:        "no extension headers",
			packet:      append(composeIPv6Packet(17), "foobar"...),
			want:        17,
			wantPayload: []byte("foobar"),
		},
		{
			name:        "all extension headers",
			packet:      append(composeIPv6Packet(ipProtoHopByHop, ipProtoDestOpts, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts, 6), "foobar"...),
			want:        6,
			wantPayload: []byte("foobar"),
		},
		{
			name:        "ESP",
			packet:      append(composeIPv6Packet(ipProtoDestOpts, 50), "foobar"...),
			want:        50,
			wantPayload: []byte("foobar"),
		},
		{
			name:   "fragment at a non-zero offset",
			packet: fragment,
			want:   ipProtoFragment,
		},
		{
			name:    "missing header",
			packet:  composeIPv6Packet(ipProtoDestOpts, 17)[:ipv6.HeaderLen],
			wantErr: "truncated",
		},
		{
			name:    "header longer than the packet",
			packet:  composeIPv6Packet(ipProtoDestOpts, 17)[:50],
			wantErr: "truncated",
		},
		{
			name:    "misplaced Hop-by-Hop Options header",
			packet:  composeIPv6Packet(ipProtoDestOpts, ipProtoHopByHop, 17),
			wantErr: "misplaced",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proto, payload, err := ipv6UpperLayerProtocol(tt.packet)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, proto)
			require.Equal(t, tt.wantPayload, payload)
		})
	}
}
