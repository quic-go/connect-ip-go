package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	ossfuzzseeds "github.com/quic-go/go-ossfuzz-seeds"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/stretchr/testify/require"
)

var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
	0x00, 0x00, 59, 64, // Payload Length, Next Header, Hop Limit
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // Destination IP
}

// marshalIPv4Header marshals an IPv4 header, and sets the Total Length and a valid header checksum.
func marshalIPv4Header(t *testing.T, hdr *ipv4.Header) []byte {
	t.Helper()
	b, err := hdr.Marshal()
	require.NoError(t, err)
	// on some platforms (e.g. macOS), Marshal uses the host byte order for the Total Length
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(b))
	return b
}

type mockStream struct {
	reading         []byte
	toRead          <-chan []byte
	sendDatagramErr error
	writeStarted    chan struct{}
	written         chan<- []byte
}

var _ http3Stream = &mockStream{}

func (m *mockStream) StreamID() quic.StreamID { panic("implement me") }
func (m *mockStream) Read(p []byte) (int, error) {
	if len(m.reading) == 0 {
		var ok bool
		if m.reading, ok = <-m.toRead; !ok {
			return 0, io.EOF
		}
	}
	n := copy(p, m.reading)
	m.reading = m.reading[n:]
	return n, nil
}
func (m *mockStream) CancelRead(quic.StreamErrorCode) {}
func (m *mockStream) Write(p []byte) (int, error) {
	if m.writeStarted != nil {
		close(m.writeStarted)
		m.writeStarted = nil
	}
	if m.written != nil {
		m.written <- bytes.Clone(p)
	}
	return len(p), nil
}
func (m *mockStream) Close() error                     { return nil }
func (m *mockStream) CancelWrite(quic.StreamErrorCode) {}
func (m *mockStream) Context() context.Context         { return context.Background() }
func (m *mockStream) SetWriteDeadline(time.Time) error { return nil }
func (m *mockStream) SetReadDeadline(time.Time) error  { return nil }
func (m *mockStream) SetDeadline(time.Time) error      { return nil }
func (m *mockStream) SendDatagram(data []byte) error   { return m.sendDatagramErr }
func (m *mockStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCapsuleWriteQueueLimit(t *testing.T) {
	writes := make(chan []byte)
	writeStarted := make(chan struct{})
	conn := newProxiedConn(&mockStream{
		writeStarted: writeStarted,
		written:      writes,
	}, nil)
	t.Cleanup(func() { conn.Close() })

	require.NoError(t, conn.AssignAddresses(nil))
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("capsule write did not start")
	}

	for range maxQueuedCapsules {
		require.NoError(t, conn.AssignAddresses(nil))
	}
	go func() {
		_, _ = conn.Routes(context.Background()) // wait for shutdown before releasing the mock writer
		for range maxQueuedCapsules + 1 {
			<-writes
		}
	}()
	require.ErrorContains(t, conn.AssignAddresses(nil), "capsule queue full")
	require.ErrorIs(t, conn.AssignAddresses(nil), net.ErrClosed)
}

func TestCapsuleReceiveQueueLimit(t *testing.T) {
	for _, name := range []string{"assignments", "requests"} {
		t.Run(name, func(t *testing.T) {
			var data []byte
			for i := range maxQueuedCapsules + 1 {
				if name == "assignments" {
					data = (&addressAssignCapsule{}).append(data)
				} else {
					data = (&addressRequestCapsule{
						RequestIDs: []AddressRequestID{AddressRequestID(i + 1)},
						Prefixes:   []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
					}).append(data)
				}
			}
			conn := newProxiedConn(&mockStream{reading: data}, nil)
			t.Cleanup(func() { conn.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := conn.Routes(ctx)
			require.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

func TestDNSConfiguration(t *testing.T) {
	cfg := []DNSConfiguration{
		{
			Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.53")},
				IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::53")},
				AuthenticationDomainName: "resolver.example.",
				ServiceParameters: map[dnsmessage.SVCParamKey][]byte{
					dnsmessage.SVCParamPort: {0x21, 0x35},
				},
			}},
			InternalDomains: []string{"internal.example."},
			SearchDomains:   []string{"internal.example.", "example."},
		},
		{
			Nameservers: []DNSNameserver{{
				ServicePriority: 2,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("198.51.100.53")},
			}},
			InternalDomains: []string{"other.example."},
		},
	}

	t.Run("send", func(t *testing.T) {
		written := make(chan []byte)
		writeStarted := make(chan struct{})
		conn := newProxiedConn(&mockStream{writeStarted: writeStarted, written: written}, nil)
		t.Cleanup(func() { conn.Close() })

		require.NoError(t, conn.AssignAddresses(nil))
		select {
		case <-writeStarted:
		case <-time.After(time.Second):
			t.Fatal("capsule write did not start")
		}
		require.NoError(t, conn.SendDNSConfiguration(cfg))
		cfg[0].Nameservers[0].ServicePriority = 42
		<-written // unblock the address assignment write
		data := <-written
		cfg[0].Nameservers[0].ServicePriority = 1

		typ, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
		require.NoError(t, err)
		require.Equal(t, capsuleTypeDNSAssign, typ)
		capsule, err := parseDNSAssignCapsule(cr)
		require.NoError(t, err)
		require.Equal(t, cfg, capsule.DNSConfigurations)
	})

	t.Run("receive", func(t *testing.T) {
		toRead := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: toRead}, nil)
		toRead <- (&dnsAssignCapsule{DNSConfigurations: cfg}).append(nil)

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		received, err := conn.ReceiveDNSConfiguration(ctx)
		require.NoError(t, err)
		require.Equal(t, cfg, received)
	})

	t.Run("invalid", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.ErrorContains(t,
			conn.SendDNSConfiguration([]DNSConfiguration{
				{Nameservers: []DNSNameserver{{ServicePriority: 0}}},
			}),
			"service priority must not be zero",
		)
		require.ErrorContains(t,
			conn.SendDNSConfiguration([]DNSConfiguration{
				{Nameservers: []DNSNameserver{{
					ServicePriority: 1,
					IPv4Addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::1")},
				}}},
			}),
			"non-IPv4 address",
		)
		require.ErrorContains(t,
			conn.SendDNSConfiguration([]DNSConfiguration{
				{
					InternalDomains: []string{"bücher.example."},
				},
			}),
			"invalid internal domain name: must use IDNA A-label form",
		)
	})
}

func TestPREF64Configuration(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("2001:db8:1200::/40"),
		netip.MustParsePrefix("2001:db8:0:0:1::/32"),
	}

	t.Run("send", func(t *testing.T) {
		written := make(chan []byte)
		writeStarted := make(chan struct{})
		conn := newProxiedConn(&mockStream{writeStarted: writeStarted, written: written}, nil)
		t.Cleanup(func() { conn.Close() })

		require.NoError(t, conn.AssignAddresses(nil))
		select {
		case <-writeStarted:
		case <-time.After(time.Second):
			t.Fatal("capsule write did not start")
		}
		require.NoError(t, conn.SendPREF64Configuration(prefixes))
		prefixes[0] = netip.MustParsePrefix("2001:db8::/32")
		<-written // unblock the address assignment write
		data := <-written
		prefixes[0] = netip.MustParsePrefix("64:ff9b::/96")

		typ, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
		require.NoError(t, err)
		require.Equal(t, capsuleTypePREF64, typ)
		capsule, err := parsePREF64Capsule(cr)
		require.NoError(t, err)
		require.Equal(t, prefixes, capsule.Prefixes)
	})

	t.Run("receive and clear", func(t *testing.T) {
		toRead := make(chan []byte, 2)
		conn := newProxiedConn(&mockStream{toRead: toRead}, nil)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()

		toRead <- (&pref64Capsule{Prefixes: prefixes}).append(nil)
		received, err := conn.ReceivePREF64Configuration(ctx)
		require.NoError(t, err)
		require.Equal(t, prefixes, received)

		toRead <- (&pref64Capsule{}).append(nil)
		received, err = conn.ReceivePREF64Configuration(ctx)
		require.NoError(t, err)
		require.Empty(t, received)
	})

	t.Run("invalid", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.ErrorContains(t,
			conn.SendPREF64Configuration([]netip.Prefix{
				netip.MustParsePrefix("192.0.2.0/24"),
			}),
			"not an IPv6 prefix",
		)
		require.ErrorContains(t,
			conn.SendPREF64Configuration([]netip.Prefix{
				netip.MustParsePrefix("2001:db8::/80"),
			}),
			"invalid prefix length",
		)
	})
}

func TestIncomingDatagrams(t *testing.T) {
	t.Run("empty packets", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket([]byte{}),
			"connect-ip: empty packet",
		)
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: unknown IP versions: 5",
		)
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data[:ipv4.HeaderLen-1]),
			"connect-ip: IPv4 packet too short",
		)
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1]),
			"connect-ip: IPv6 packet too short",
		)
	})

	t.Run("IPv6 payload length mismatch", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(composeIPv6Packet(ipProtoDestOpts, 17)[:50]),
			"connect-ip: IPv6 payload length (16) doesn't match packet size (10)",
		)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(append(composeIPv6Packet(17), make([]byte, 8)...)),
			"connect-ip: IPv6 payload length (0) doesn't match packet size (8)",
		)
	})

	t.Run("invalid IPv4 checksum", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data := marshalIPv4Header(t, &ipv4.Header{
			Src: net.IPv4(1, 2, 3, 4),
			Dst: net.IPv4(159, 70, 42, 98),
			Len: 20,
		})
		data[10]++ // corrupt the checksum
		require.ErrorContains(t, conn.handleIncomingProxiedPacket(data), "connect-ip: invalid IPv4 header checksum")
	})

	t.Run("IPv4 total length mismatch", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data := marshalIPv4Header(t, &ipv4.Header{
			Src: net.IPv4(1, 2, 3, 4),
			Dst: net.IPv4(159, 70, 42, 98),
			Len: 20,
		})
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(append(data, 0, 0, 0, 0)),
			"connect-ip: IPv4 total length (20) doesn't match packet size (24)",
		)
		binary.BigEndian.PutUint16(data[2:4], 24)
		binary.BigEndian.PutUint16(data[10:12], calculateIPv4Checksum(data))
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: IPv4 total length (24) doesn't match packet size (20)",
		)
	})

	t.Run("invalid source address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 11),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}
		data := marshalIPv4Header(t, hdr)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram source address not allowed: 192.168.0.11",
		)
	})

	t.Run("invalid destination address", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3")},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
		}
		data := marshalIPv4Header(t, hdr)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		// 10.1.2.4 is outside the range of allowed addresses
		hdr.Dst = net.IPv4(10, 1, 2, 4)
		data = marshalIPv4Header(t, hdr)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.4 (protocol: 0)",
		)
	})

	t.Run("invalid IP protocol", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}))
		require.NoError(t, conn.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		}))
		hdr := &ipv4.Header{
			Src:      net.IPv4(192, 168, 0, 10),
			Dst:      net.IPv4(10, 1, 2, 3),
			Len:      20,
			Checksum: 89,
			Protocol: 42,
		}
		data := marshalIPv4Header(t, hdr)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		hdr.Protocol = 41
		data = marshalIPv4Header(t, hdr)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.3 (protocol: 41)",
		)

		// ICMP is always allowed
		hdr.Protocol = ipProtoICMP
		data = marshalIPv4Header(t, hdr)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})

	t.Run("IPv6 extension headers", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.NoError(t, conn.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("::"), EndIP: netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IPProtocol: 17},
		}))
		require.NoError(t, conn.handleIncomingProxiedPacket(composeIPv6Packet(ipProtoHopByHop, ipProtoFragment, 17)))
		require.ErrorContains(t, conn.handleIncomingProxiedPacket(composeIPv6Packet(ipProtoDestOpts, 6)), "(protocol: 6)")
		// ICMP is always allowed
		require.NoError(t, conn.handleIncomingProxiedPacket(composeIPv6Packet(ipProtoHopByHop, ipProtoICMPv6)))

		// fragments at non-zero offsets are allowed regardless of the protocol
		fragment := composeIPv6Packet(ipProtoFragment, ipProtoDestOpts, 6)
		fragment[ipv6.HeaderLen+2] = 1 // Fragment Offset
		require.NoError(t, conn.handleIncomingProxiedPacket(fragment))
	})

	t.Run("packet from assigned address", func(t *testing.T) {
		readChan := make(chan []byte, 1)
		conn := newProxiedConn(&mockStream{toRead: readChan}, nil)

		hdr := &ipv4.Header{
			Src:      net.IPv4(159, 70, 42, 98),
			Dst:      net.IPv4(192, 168, 0, 10),
			Len:      20,
			Checksum: 89,
		}
		data := marshalIPv4Header(t, hdr)
		require.Error(t, conn.handleIncomingProxiedPacket(data), "connect-ip: datagram destination address")

		// now assign 192.168.0.11 to this connection
		readChan <- (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := conn.ReceiveAddressAssignment(ctx)
		require.NoError(t, err)
		// after processing the address assignment, this is a valid packet
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
	})
}

func TestSkipUnknownCapsule(t *testing.T) {
	readChan := make(chan []byte, 1)
	conn := newProxiedConn(&mockStream{toRead: readChan}, nil)

	data := quicvarint.Append(nil, 42)
	data = quicvarint.Append(data, 3)
	data = append(data, "foo"...)
	data = (&addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
	}).append(data)
	readChan <- data

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)
	require.Equal(t, []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}}, assigned)
}

func FuzzIncomingDatagram(f *testing.F) {
	// OSS-Fuzz runs this function once per input, so the connection must not leak goroutines.
	readChan := make(chan []byte)
	defer close(readChan)
	conn := newProxiedConn(&mockStream{toRead: readChan}, nil)
	defer conn.Close()
	require.NoError(f, conn.AssignAddresses([]netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::0/64"),
	}))
	require.NoError(f, conn.AdvertiseRoute([]IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 42},
	}))

	// Don't use marshalIPv4Header here: OSS-Fuzz builds replace *testing.F with a type
	// that doesn't implement testing.T.
	ipv4Header, err := (&ipv4.Header{
		Src: net.IPv4(1, 2, 3, 4),
		Dst: net.IPv4(159, 70, 42, 98),
		Len: 20,
	}).Marshal()
	require.NoError(f, err)
	binary.BigEndian.PutUint16(ipv4Header[2:4], uint16(len(ipv4Header)))
	binary.BigEndian.PutUint16(ipv4Header[10:12], calculateIPv4Checksum(ipv4Header))

	corpus := ossfuzzseeds.New(f)
	corpus.Add(ipv4Header)
	corpus.Add(ipv6Header)
	corpus.Add(composeIPv6Packet(ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts, 42))

	f.Fuzz(func(t *testing.T, data []byte) {
		conn.handleIncomingProxiedPacket(data)
	})
}

func TestSendingDatagrams(t *testing.T) {
	t.Run("empty packet", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		_, err := conn.composeDatagram([]byte{})
		require.ErrorContains(t, err, "connect-ip: empty packet")
	})

	t.Run("invalid IP version", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data := make([]byte, 20)
		data[0] = 5 << 4 // IPv5
		_, err := conn.composeDatagram(data)
		require.ErrorContains(t, err, "connect-ip: unknown IP versions: 5")
	})

	t.Run("IPv4 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data, err := (&ipv4.Header{
			Src:      net.IPv4(1, 2, 3, 4),
			Dst:      net.IPv4(159, 70, 42, 98),
			Len:      20,
			Checksum: 89,
		}).Marshal()
		require.NoError(t, err)
		_, err = conn.composeDatagram(data[:ipv4.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv4 packet too short")
	})

	t.Run("invalid IPv4 checksum", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data := marshalIPv4Header(t, &ipv4.Header{
			Src: net.IPv4(1, 2, 3, 4),
			Dst: net.IPv4(159, 70, 42, 98),
			Len: 20,
			TTL: 64,
		})
		data[10]++ // corrupt the checksum
		_, err := conn.composeDatagram(data)
		require.ErrorContains(t, err, "connect-ip: invalid IPv4 header checksum")
	})

	t.Run("IPv4 total length mismatch", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		data := marshalIPv4Header(t, &ipv4.Header{
			Src: net.IPv4(1, 2, 3, 4),
			Dst: net.IPv4(159, 70, 42, 98),
			Len: 20,
			TTL: 64,
		})
		_, err := conn.composeDatagram(append(data, 0, 0, 0, 0))
		require.ErrorContains(t, err, "connect-ip: IPv4 total length (20) doesn't match packet size (24)")
		binary.BigEndian.PutUint16(data[2:4], 24)
		binary.BigEndian.PutUint16(data[10:12], calculateIPv4Checksum(data))
		_, err = conn.composeDatagram(data)
		require.ErrorContains(t, err, "connect-ip: IPv4 total length (24) doesn't match packet size (20)")
	})

	t.Run("IPv4 header with options", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("159.70.42.98/32")}))
		data := marshalIPv4Header(t, &ipv4.Header{
			Src:     net.IPv4(1, 2, 3, 4),
			Dst:     net.IPv4(159, 70, 42, 98),
			Len:     20,
			TTL:     64,
			Options: []byte{1, 1, 1, 0}, // three No Operation options, End of Options List
		})
		datagram, err := conn.composeDatagram(data)
		require.NoError(t, err)
		packet := datagram[len(contextIDZero):]
		require.Equal(t, uint8(63), packet[8])
		require.NoError(t, validateIPv4Checksum(packet))
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		_, err := conn.composeDatagram(ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})

	t.Run("IPv6 payload length mismatch", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		_, err := conn.composeDatagram(composeIPv6Packet(ipProtoDestOpts, 17)[:50])
		require.ErrorContains(t, err, "connect-ip: IPv6 payload length (16) doesn't match packet size (10)")
		_, err = conn.composeDatagram(append(composeIPv6Packet(17), make([]byte, 8)...))
		require.ErrorContains(t, err, "connect-ip: IPv6 payload length (0) doesn't match packet size (8)")
	})

	t.Run("address and protocol checks", func(t *testing.T) {
		// the peer assigned 192.168.0.10 to us, and advertised a route for IP protocol 42
		data := (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)
		data = (&routeAdvertisementCapsule{IPAddressRanges: []IPRoute{
			{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		}}).append(data)
		conn := newProxiedConn(&mockStream{reading: data}, nil)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := conn.Routes(ctx) // wait until both capsules have been processed
		require.NoError(t, err)
		// we assigned 172.16.0.1 to the peer, and advertised a route for IP protocol 6
		require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("172.16.0.1/32")}))
		require.NoError(t, conn.AdvertiseRoute([]IPRoute{
			{StartIP: netip.MustParseAddr("192.168.1.0"), EndIP: netip.MustParseAddr("192.168.1.255"), IPProtocol: 6},
		}))

		for _, tt := range []struct {
			name     string
			src, dst string
			proto    int
			wantErr  string
		}{
			{name: "assigned source", src: "192.168.0.10", dst: "10.1.2.3", proto: 42},
			{name: "unassigned source", src: "192.168.0.11", dst: "10.1.2.3", proto: 42, wantErr: "source address not allowed: 192.168.0.11"},
			{name: "source covered by our route, for any protocol", src: "192.168.1.1", dst: "10.1.2.3", proto: 42},
			{name: "destination outside the peer's routes", src: "192.168.0.10", dst: "10.1.2.4", proto: 42, wantErr: "not allowed: 10.1.2.4 (protocol: 42)"},
			{name: "protocol not allowed by the peer's route", src: "192.168.0.10", dst: "10.1.2.3", proto: 41, wantErr: "not allowed: 10.1.2.3 (protocol: 41)"},
			{name: "destination assigned to the peer, for any protocol", src: "192.168.0.10", dst: "172.16.0.1", proto: 41},
		} {
			t.Run(tt.name, func(t *testing.T) {
				packet := marshalIPv4Header(t, &ipv4.Header{
					Src:      net.ParseIP(tt.src),
					Dst:      net.ParseIP(tt.dst),
					Protocol: tt.proto,
					Len:      20,
					TTL:      64,
				})
				orig := bytes.Clone(packet)
				_, err := conn.composeDatagram(packet)
				if tt.wantErr == "" {
					require.NoError(t, err)
					return
				}
				require.ErrorContains(t, err, tt.wantErr)
				require.Equal(t, orig, packet) // dropped packets aren't modified
			})
		}
	})
}

func TestSendLargeDatagrams(t *testing.T) {
	str := &mockStream{sendDatagramErr: &quic.DatagramTooLargeError{}}
	conn := newProxiedConn(str, nil)
	// the peer didn't assign any addresses to us, so the source address isn't restricted
	require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("5.6.7.8/32")}))
	data := marshalIPv4Header(t, &ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	})
	icmp, err := conn.WritePacket(data)
	require.NoError(t, err)
	require.NotNil(t, icmp)
}

func TestWritePacketAfterRemoteClose(t *testing.T) {
	toRead := make(chan []byte)
	conn := newProxiedConn(&mockStream{toRead: toRead}, nil)
	close(toRead) // the peer closes the stream

	_, err := conn.Routes(context.Background())
	require.ErrorIs(t, err, net.ErrClosed)
	// The mock stream always accepts datagrams,
	// like an HTTP/3 stream does until its send side is closed.
	_, err = conn.WritePacket(bytes.Clone(ipv6Header))
	require.ErrorIs(t, err, net.ErrClosed)
}
