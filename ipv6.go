package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/net/ipv6"
)

// IPv6 extension headers listed in Section 4 of RFC 8200, except for ESP.
const (
	ipProtoHopByHop = 0
	ipProtoRouting  = 43
	ipProtoFragment = 44
	ipProtoAH       = 51
	ipProtoDestOpts = 60
)

var errTruncatedExtensionHeader = errors.New("connect-ip: malformed datagram: truncated IPv6 extension header")

// validateIPv6PayloadLength checks that the Payload Length field matches the packet size.
// An HTTP Datagram contains exactly one IP packet, with no trailing bytes (Section 6 of RFC 9484).
func validateIPv6PayloadLength(b []byte) error {
	// A Payload Length of zero is also used by jumbograms (RFC 2675), which are rejected here.
	// Jumbograms are larger than 65535 bytes, and therefore never fit into a QUIC DATAGRAM frame.
	if l := int(binary.BigEndian.Uint16(b[4:6])); ipv6.HeaderLen+l != len(b) {
		return fmt.Errorf("connect-ip: IPv6 payload length (%d) doesn't match packet size (%d)", l, len(b)-ipv6.HeaderLen)
	}
	return nil
}

// ipv6UpperLayerProtocol walks the extension header chain of an IPv6 packet
// and returns the upper-layer protocol number.
//
// Only the extension headers listed in Section 4 of RFC 8200 are walked, except for ESP,
// which encrypts everything following it. To keep the implementation simple, all other
// extension headers are returned as the upper-layer protocol.
//
// Fragments at non-zero fragment offsets don't contain the upper-layer header.
// For these, ipProtoFragment is returned.
func ipv6UpperLayerProtocol(b []byte) (uint8, error) {
	next := b[6]
	pos := ipv6.HeaderLen
	for {
		switch next {
		case ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts:
		default:
			return next, nil
		}
		// the Hop-by-Hop Options header must immediately follow the IPv6 header
		if next == ipProtoHopByHop && pos != ipv6.HeaderLen {
			return 0, errors.New("connect-ip: malformed datagram: misplaced Hop-by-Hop Options header")
		}
		// each of these headers is at least 8 bytes long
		if len(b) < pos+8 {
			return 0, errTruncatedExtensionHeader
		}
		var hdrLen int
		switch next {
		case ipProtoFragment:
			// the 13 bit fragment offset is non-zero for all but the first fragment
			if binary.BigEndian.Uint16(b[pos+2:pos+4])>>3 != 0 {
				return ipProtoFragment, nil
			}
			hdrLen = 8
		case ipProtoAH:
			// the length is encoded in 4-byte units, minus 2 (see Section 2.2 of RFC 4302)
			hdrLen = (int(b[pos+1]) + 2) * 4
		default:
			// the length is encoded in 8-byte units, not including the first 8 bytes
			hdrLen = (int(b[pos+1]) + 1) * 8
		}
		if len(b) < pos+hdrLen {
			return 0, errTruncatedExtensionHeader
		}
		next = b[pos]
		pos += hdrLen
	}
}
