package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

// fixLengthsAndChecksum sets the length fields and the IPv4 header checksum to match the packet.
func fixLengthsAndChecksum(b []byte) {
	switch {
	case len(b) >= ipv4.HeaderLen && ipVersion(b) == 4:
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		if hdrLen := int(b[0]&0x0f) * 4; hdrLen <= len(b) {
			binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(b[:hdrLen]))
		}
	case len(b) >= ipv6.HeaderLen && ipVersion(b) == 6:
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-ipv6.HeaderLen))
	}
}

var (
	fuzzPeerAddresses = []netip.Prefix{ // addresses we assign to the peer
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8:a::/64"),
	}
	fuzzAssignedAddresses = []AssignedAddress{ // addresses the peer assigns to us
		{IPPrefix: netip.MustParsePrefix("198.51.100.1/32")},
		{IPPrefix: netip.MustParsePrefix("2001:db8:b::1/128")},
	}
	fuzzLocalRoutes = []IPRoute{ // routes we advertise to the peer
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.255.255"), IPProtocol: 17},
		{StartIP: netip.MustParseAddr("fd00::"), EndIP: netip.MustParseAddr("fd00::ffff"), IPProtocol: 17},
	}
	fuzzPeerRoutes = []IPRoute{ // routes the peer advertises to us
		{StartIP: netip.MustParseAddr("203.0.113.0"), EndIP: netip.MustParseAddr("203.0.113.255")},
		{StartIP: netip.MustParseAddr("2001:db8:c::"), EndIP: netip.MustParseAddr("2001:db8:c::ffff"), IPProtocol: 6},
	}
)

// newFuzzConn returns a connection after exchanging the selected address assignments
// and route advertisements. Any of them might not have been sent (yet).
// The returned function closes the connection.
func newFuzzConn(
	t *testing.T,
	hasPeerAddresses, hasAssignedAddresses, hasLocalRoutes, hasPeerRoutes bool,
	datagrams <-chan []byte,
	sendDatagram func([]byte) error,
) (*Conn, func()) {
	// The peer assigns addresses and advertises routes to us by sending capsules.
	var capsules []byte
	if hasAssignedAddresses {
		capsules = (&addressAssignCapsule{AssignedAddresses: fuzzAssignedAddresses}).append(capsules)
	}
	if hasPeerRoutes {
		capsules = (&routeAdvertisementCapsule{IPAddressRanges: fuzzPeerRoutes}).append(capsules)
	}
	toRead := make(chan []byte)
	conn := newProxiedConn(&mockStream{
		reading:      capsules,
		toRead:       toRead,
		datagrams:    datagrams,
		sendDatagram: sendDatagram,
	}, nil)
	closeConn := func() {
		conn.Close()
		close(toRead)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if hasAssignedAddresses {
		_, err := conn.ReceiveAddressAssignment(ctx)
		require.NoError(t, err)
	}
	if hasPeerRoutes {
		_, err := conn.Routes(ctx)
		require.NoError(t, err)
	}
	if hasPeerAddresses {
		require.NoError(t, conn.AssignAddresses(fuzzPeerAddresses))
	}
	if hasLocalRoutes {
		require.NoError(t, conn.AdvertiseRoute(fuzzLocalRoutes))
	}
	return conn, closeConn
}

// Don't use marshalIPv4Header here: OSS-Fuzz builds replace *testing.F with a type
// that doesn't implement testing.T.
func fuzzIPv4Packet(t require.TestingT, src, dst string, proto uint8, options []byte) []byte {
	hdr, err := (&ipv4.Header{
		Src:      net.ParseIP(src),
		Dst:      net.ParseIP(dst),
		Len:      ipv4.HeaderLen,
		Protocol: int(proto),
		TTL:      64,
		Options:  options,
	}).Marshal()
	require.NoError(t, err)
	b := append(hdr, make([]byte, 8)...) // payload
	// on some platforms (e.g. macOS), Marshal uses the host byte order for the Total Length
	fixLengthsAndChecksum(b)
	return b
}

func fuzzIPv6Packet(src, dst string, nextHeaders ...uint8) []byte {
	b := composeIPv6Packet(nextHeaders...)
	copy(b[8:24], netip.MustParseAddr(src).AsSlice())
	copy(b[24:40], netip.MustParseAddr(dst).AsSlice())
	return b
}

func fuzzICMPTooLarge(t require.TestingT, packet []byte) []byte {
	icmp, err := composeICMPTooLargePacket(packet, 1280)
	require.NoError(t, err)
	return icmp
}

func FuzzIncomingDatagram(f *testing.F) {
	corpus := ossfuzzseeds.New(f)
	for _, packet := range [][]byte{
		// packets to an address the peer assigned to us
		fuzzIPv4Packet(f, "192.0.2.1", "198.51.100.1", 17, nil),
		fuzzIPv6Packet("2001:db8:a::1", "2001:db8:b::1", 17),
		// packets to a route we advertised
		fuzzIPv4Packet(f, "192.0.2.1", "10.0.0.1", 17, []byte{1, 1, 1, 0}), // three No Operation options, End of Options List
		fuzzIPv6Packet("2001:db8:a::1", "fd00::1", ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts, 17),
		// ICMP errors from routers on the path, for packets we sent to one of the peer's routes
		fuzzICMPTooLarge(f, fuzzIPv4Packet(f, "198.51.100.1", "203.0.113.7", 17, nil)),
		fuzzICMPTooLarge(f, fuzzIPv6Packet("2001:db8:b::1", "2001:db8:c::7", 6)),
	} {
		corpus.Add(true, true, true, true, true, append([]byte{0}, packet...)) // context ID 0
	}

	f.Fuzz(func(t *testing.T, hasPeerAddresses, hasAssignedAddresses, hasLocalRoutes, hasPeerRoutes, fixHeader bool, data []byte) {
		datagrams := make(chan []byte, 1)
		conn, closeConn := newFuzzConn(t, hasPeerAddresses, hasAssignedAddresses, hasLocalRoutes, hasPeerRoutes, datagrams, nil)
		defer closeConn()

		// Without fixing the header, almost any mutation of an IPv4 header would invalidate the checksum,
		// and the packet would be dropped before reaching the forwarding logic.
		if fixHeader {
			data = bytes.Clone(data) // the fuzzer's input must not be modified
			if _, l, err := quicvarint.Parse(data); err == nil {
				fixLengthsAndChecksum(data[l:])
			}
		}
		orig := bytes.Clone(data)
		datagrams <- data
		b := make([]byte, len(data))
		n, err := conn.ReadPacket(b)
		require.Equal(t, orig, data, "reading a packet must not modify the datagram")
		if err == nil {
			require.Equal(t, data[len(data)-n:], b[:n], "the packet must be returned unmodified")
		}
	})
}

func FuzzWritePacket(f *testing.F) {
	corpus := ossfuzzseeds.New(f)
	for _, packet := range [][]byte{
		// packets from an address the peer assigned to us, to an address we assigned to the peer
		fuzzIPv4Packet(f, "198.51.100.1", "192.0.2.1", 17, nil),
		fuzzIPv6Packet("2001:db8:b::1", "2001:db8:a::1", 17),
		// packets from a route we advertised, to a route the peer advertised
		fuzzIPv4Packet(f, "10.0.0.1", "203.0.113.7", 17, []byte{1, 1, 1, 0}), // three No Operation options, End of Options List
		fuzzIPv6Packet("fd00::1", "2001:db8:c::7", ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts, 6),
		// ICMP errors from routers on the path, for packets the peer sent to one of our routes
		fuzzICMPTooLarge(f, fuzzIPv4Packet(f, "192.0.2.1", "10.0.0.1", 17, nil)),
		fuzzICMPTooLarge(f, fuzzIPv6Packet("2001:db8:a::1", "fd00::1", 17)),
	} {
		corpus.Add(true, true, true, true, true, false, packet)
		corpus.Add(true, true, true, true, true, true, packet)
	}

	// If tooLarge is set, sending the datagram fails, as if the packet didn't fit into a datagram.
	f.Fuzz(func(t *testing.T, hasPeerAddresses, hasAssignedAddresses, hasLocalRoutes, hasPeerRoutes, fixHeader, tooLarge bool, data []byte) {
		var sent []byte
		conn, closeConn := newFuzzConn(t, hasPeerAddresses, hasAssignedAddresses, hasLocalRoutes, hasPeerRoutes, nil, func(b []byte) error {
			sent = b
			if tooLarge {
				return &quic.DatagramTooLargeError{}
			}
			return nil
		})
		defer closeConn()

		b := bytes.Clone(data) // WritePacket modifies the packet, but the fuzzer's input must not be modified
		// Without fixing the header, almost any mutation of an IPv4 header would invalidate the checksum,
		// and the packet would be dropped before reaching the forwarding logic.
		if fixHeader {
			fixLengthsAndChecksum(b)
		}
		orig := bytes.Clone(b)
		icmp, err := conn.WritePacket(b)
		require.NoError(t, err)
		if sent == nil {
			require.Empty(t, icmp)
			require.Equal(t, orig, b, "dropped packets must not be modified")
			return
		}
		require.Equal(t, append([]byte{0}, b...), sent) // context ID 0
		if tooLarge {
			_, _, _, err := parseIPHeader(icmp)
			require.NoError(t, err, "invalid ICMP packet")
		} else {
			require.Empty(t, icmp)
		}

		// Only the TTL / Hop Limit (and the IPv4 header checksum) may be modified.
		_, _, _, err = parseIPHeader(b)
		require.NoError(t, err, "the forwarded packet must be valid")
		switch ipVersion(orig) {
		case 4:
			require.Greater(t, orig[8], uint8(1), "forwarded a packet with an expired TTL")
			orig[8]--
			copy(orig[10:12], b[10:12]) // validated by parseIPHeader
		case 6:
			require.Greater(t, orig[7], uint8(1), "forwarded a packet with an expired Hop Limit")
			orig[7]--
		}
		require.Equal(t, orig, b)
	})
}
