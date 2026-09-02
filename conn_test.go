package connectip

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

var ipv6Header = []byte{
	0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
	0x00, 0x20, 59, 64, // Payload Length, Next Header, Hop Limit
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Source IP
	0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x48, // Destination IP
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
		m.reading = <-m.toRead
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

func TestCapsuleQueueLimit(t *testing.T) {
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
	require.ErrorContains(t, conn.AssignAddresses(nil), "capsule queue full")
	require.ErrorIs(t, conn.AssignAddresses(nil), net.ErrClosed)

	// Let the writer finish the in-progress write and observe the closed connection.
	<-writes
}

func TestDNSConfiguration(t *testing.T) {
	cfg := []DNSConfiguration{
		{
			Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.53")},
				IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::53")},
				AuthenticationDomainName: "resolver.example",
				ServiceParameters:        []byte{0, 3, 0, 2, 0x21, 0x35},
			}},
			InternalDomains: []string{"internal.example"},
			SearchDomains:   []string{"internal.example", "example"},
		},
		{
			Nameservers: []DNSNameserver{{
				ServicePriority: 2,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("198.51.100.53")},
			}},
			InternalDomains: []string{"other.example"},
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
					InternalDomains: []string{"bücher.example"},
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
			"connect-ip: malformed datagram: too short",
		)
	})

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(ipv6Header[:ipv6.HeaderLen-1]),
			"connect-ip: malformed datagram: too short",
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
		data, err := hdr.Marshal()
		require.NoError(t, err)
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
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		// 10.1.2.4 is outside the range of allowed addresses
		hdr.Dst = net.IPv4(10, 1, 2, 4)
		data, err = hdr.Marshal()
		require.NoError(t, err)
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
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))

		hdr.Protocol = 41
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.ErrorContains(t,
			conn.handleIncomingProxiedPacket(data),
			"connect-ip: datagram destination address / protocol not allowed: 10.1.2.3 (protocol: 41)",
		)

		// ICMP is always allowed
		hdr.Protocol = ipProtoICMP
		data, err = hdr.Marshal()
		require.NoError(t, err)
		require.NoError(t, conn.handleIncomingProxiedPacket(data))
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
		data, err := hdr.Marshal()
		require.NoError(t, err)
		require.Error(t, conn.handleIncomingProxiedPacket(data), "connect-ip: datagram destination address")

		// now assign 192.168.0.11 to this connection
		readChan <- (&addressAssignCapsule{
			AssignedAddresses: []AssignedAddress{{IPPrefix: netip.MustParsePrefix("192.168.0.10/32")}},
		}).append(nil)

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.LocalPrefixes(ctx)
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
	prefixes, err := conn.LocalPrefixes(ctx)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.168.0.10/32")}, prefixes)
}

func FuzzIncomingDatagram(f *testing.F) {
	conn := newProxiedConn(&mockStream{}, nil)
	require.NoError(f, conn.AssignAddresses([]netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("2001:db8::0/64"),
	}))
	require.NoError(f, conn.AdvertiseRoute([]IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.1.2.3"), IPProtocol: 42},
		{StartIP: netip.MustParseAddr("2001:db8:1::"), EndIP: netip.MustParseAddr("2001:db8:1::ffff"), IPProtocol: 42},
	}))

	ipv4Header, err := (&ipv4.Header{
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(159, 70, 42, 98),
		Len:      20,
		Checksum: 89,
	}).Marshal()
	require.NoError(f, err)

	f.Add(ipv4Header)
	f.Add(ipv6Header)

	f.Fuzz(func(t *testing.T, data []byte) {
		conn.handleIncomingProxiedPacket(data)
	})
}

func TestSendingDatagrams(t *testing.T) {
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

	t.Run("IPv6 packet too short", func(t *testing.T) {
		conn := newProxiedConn(&mockStream{}, nil)
		_, err := conn.composeDatagram(ipv6Header[:ipv6.HeaderLen-1])
		require.ErrorContains(t, err, "connect-ip: IPv6 packet too short")
	})
}

func TestSendLargeDatagrams(t *testing.T) {
	str := &mockStream{sendDatagramErr: &quic.DatagramTooLargeError{}}
	conn := newProxiedConn(str, nil)
	data, err := (&ipv4.Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Src:      net.IPv4(1, 2, 3, 4),
		Dst:      net.IPv4(5, 6, 7, 8),
		Protocol: 17,
	}).Marshal()
	require.NoError(t, err)
	icmp, err := conn.WritePacket(data)
	require.NoError(t, err)
	require.NotNil(t, icmp)
}
