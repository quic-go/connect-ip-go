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

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"

	"github.com/stretchr/testify/require"
)

func FuzzIncomingDatagram(f *testing.F) {
	peerAddresses := []netip.Prefix{ // addresses we assign to the peer
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8:a::/64"),
	}
	assignedAddresses := []AssignedAddress{ // addresses the peer assigns to us
		{IPPrefix: netip.MustParsePrefix("198.51.100.1/32")},
		{IPPrefix: netip.MustParsePrefix("2001:db8:b::1/128")},
	}
	localRoutes := []IPRoute{ // routes we advertise to the peer
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.255.255"), IPProtocol: 17},
		{StartIP: netip.MustParseAddr("fd00::"), EndIP: netip.MustParseAddr("fd00::ffff"), IPProtocol: 17},
	}
	peerRoutes := []IPRoute{ // routes the peer advertises to us
		{StartIP: netip.MustParseAddr("203.0.113.0"), EndIP: netip.MustParseAddr("203.0.113.255")},
		{StartIP: netip.MustParseAddr("2001:db8:c::"), EndIP: netip.MustParseAddr("2001:db8:c::ffff"), IPProtocol: 6},
	}

	// Don't use marshalIPv4Header here: OSS-Fuzz builds replace *testing.F with a type
	// that doesn't implement testing.T.
	ipv4Packet := func(src, dst string, proto uint8, options []byte) []byte {
		hdr, err := (&ipv4.Header{
			Src:      net.ParseIP(src),
			Dst:      net.ParseIP(dst),
			Len:      ipv4.HeaderLen,
			Protocol: int(proto),
			TTL:      64,
			Options:  options,
		}).Marshal()
		require.NoError(f, err)
		b := append(hdr, make([]byte, 8)...) // payload
		// on some platforms (e.g. macOS), Marshal uses the host byte order for the Total Length
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(b[:len(hdr)]))
		return b
	}
	ipv6Packet := func(src, dst string, nextHeaders ...uint8) []byte {
		b := composeIPv6Packet(nextHeaders...)
		copy(b[8:24], netip.MustParseAddr(src).AsSlice())
		copy(b[24:40], netip.MustParseAddr(dst).AsSlice())
		return b
	}
	icmpTooLarge := func(packet []byte) []byte {
		icmp, err := composeICMPTooLargePacket(packet, 1280)
		require.NoError(f, err)
		return icmp
	}

	corpus := ossfuzzseeds.New(f)
	for _, packet := range [][]byte{
		// packets to an address the peer assigned to us
		ipv4Packet("192.0.2.1", "198.51.100.1", 17, nil),
		ipv6Packet("2001:db8:a::1", "2001:db8:b::1", 17),
		// packets to a route we advertised
		ipv4Packet("192.0.2.1", "10.0.0.1", 17, []byte{1, 1, 1, 0}), // three No Operation options, End of Options List
		ipv6Packet("2001:db8:a::1", "fd00::1", ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts, 17),
		// ICMP errors from routers on the path, for packets we sent to one of the peer's routes
		icmpTooLarge(ipv4Packet("198.51.100.1", "203.0.113.7", 17, nil)),
		icmpTooLarge(ipv6Packet("2001:db8:b::1", "2001:db8:c::7", 6)),
	} {
		corpus.Add(true, true, true, true, append([]byte{0}, packet...)) // context ID 0
	}

	// Any of the address assignments and route advertisements might not have been sent (yet).
	f.Fuzz(func(t *testing.T, hasPeerAddresses, hasAssignedAddresses, hasLocalRoutes, hasPeerRoutes bool, data []byte) {
		// The peer assigns addresses and advertises routes to us by sending capsules.
		var capsules []byte
		if hasAssignedAddresses {
			capsules = (&addressAssignCapsule{AssignedAddresses: assignedAddresses}).append(capsules)
		}
		if hasPeerRoutes {
			capsules = (&routeAdvertisementCapsule{IPAddressRanges: peerRoutes}).append(capsules)
		}
		toRead := make(chan []byte)
		defer close(toRead)
		datagrams := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{reading: capsules, toRead: toRead, datagrams: datagrams}, nil)
		defer conn.Close()

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
			require.NoError(t, conn.AssignAddresses(peerAddresses))
		}
		if hasLocalRoutes {
			require.NoError(t, conn.AdvertiseRoute(localRoutes))
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
