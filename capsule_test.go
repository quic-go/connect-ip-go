package connectip

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func newCapsuleReader(t *testing.T, typ http3.CapsuleType, payload []byte) http3.CapsuleReader {
	t.Helper()

	data := quicvarint.Append(nil, uint64(typ))
	data = quicvarint.Append(data, uint64(len(payload)))
	data = append(data, payload...)
	parsedType, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
	require.NoError(t, err)
	require.Equal(t, typ, parsedType)
	return cr
}

func testIncompleteCapsule(t *testing.T, data []byte, parse func(http3.CapsuleReader) error) {
	t.Helper()

	r := bytes.NewReader(data)
	_, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.NoError(t, parse(cr))
	require.Zero(t, r.Len())
	for i := range data {
		_, cr, err := http3.NewCapsuleParser(bytes.NewReader(data[:i])).Next()
		if err != nil {
			if i == 0 {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			}
			continue
		}
		require.ErrorIs(t, parse(cr), io.ErrUnexpectedEOF)
	}
}

func TestParseAddressAssignCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337) // Request ID
	addr1 = append(addr1, 4)              // IPv4
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)             // IP Prefix Length
	addr2 := quicvarint.Append(nil, 1338) // Request ID
	addr2 = append(addr2, 6)              // IPv6
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128) // IP Prefix Length

	data := quicvarint.Append(nil, uint64(capsuleTypeAddressAssign))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	capsule, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.AssignedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestWriteAddressAssignCapsule(t *testing.T) {
	c := &addressAssignCapsule{
		AssignedAddresses: []AssignedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressAssign, typ)
	parsed, err := parseAddressAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseAddressAssignCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressAssign, func(r io.Reader) error {
		_, err := parseAddressAssignCapsule(quicvarint.NewReader(r))
		return err
	})
}

func testParseAddressCapsuleInvalid(t *testing.T, typ http3.CapsuleType, f func(r io.Reader) error) {
	t.Run("invalid IP version", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 5)              // Invalid IP version (not 4 or 6)
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 32) // IP Prefix Length
		require.ErrorContains(t, f(newCapsuleReader(t, typ, addr1)), "invalid IP version: 5")
	})

	t.Run("invalid prefix length", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337) // Request ID
		addr1 = append(addr1, 4)              // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...)
		addr1 = append(addr1, 33) // too long IP Prefix Length
		require.ErrorContains(t, f(newCapsuleReader(t, typ, addr1)), "prefix length 33 exceeds IP address length (32)")
	})

	t.Run("lower bits not covered by prefix length are not all zero", func(t *testing.T) {
		addr1 := quicvarint.Append(nil, 1337)                                    // Request ID
		addr1 = append(addr1, 4)                                                 // IPv4
		addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // non-zero lower bits
		addr1 = append(addr1, 28)                                                // IP Prefix Length
		require.ErrorContains(t, f(newCapsuleReader(t, typ, addr1)), "lower bits not covered by prefix length are not all zero")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		var data []byte
		switch typ {
		case capsuleTypeAddressAssign:
			data = (&addressAssignCapsule{
				AssignedAddresses: []AssignedAddress{
					{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.4/32")},
					{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
				},
			}).append(nil)
		case capsuleTypeAddressRequest:
			data = (&addressRequestCapsule{
				RequestedAddresses: []RequestedAddress{
					{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.4/32")},
					{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
				},
			}).append(nil)
		default:
			t.Fatalf("unexpected capsule type: %d", typ)
		}

		testIncompleteCapsule(t, data, func(r http3.CapsuleReader) error { return f(r) })
	})
}

func TestParseAddressRequestCapsule(t *testing.T) {
	addr1 := quicvarint.Append(nil, 1337) // Request ID
	addr1 = append(addr1, 4)              // IPv4
	addr1 = append(addr1, netip.AddrFrom4([4]byte{1, 2, 3, 0}).AsSlice()...)
	addr1 = append(addr1, 24)             // IP Prefix Length
	addr2 := quicvarint.Append(nil, 1338) // Request ID
	addr2 = append(addr2, 6)              // IPv6
	addr2 = append(addr2, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	addr2 = append(addr2, 128) // IP Prefix Length
	data := quicvarint.Append(nil, uint64(capsuleTypeAddressRequest))
	data = quicvarint.Append(data, uint64(len(addr1)+len(addr2))) // Length
	data = append(data, addr1...)
	data = append(data, addr2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	capsule, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]RequestedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
		capsule.RequestedAddresses,
	)
	require.Zero(t, r.Len())
}

func TestWriteAddressRequestCapsule(t *testing.T) {
	c := &addressRequestCapsule{
		RequestedAddresses: []RequestedAddress{
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("1.2.3.0/24")},
			{RequestID: 1338, IPPrefix: netip.MustParsePrefix("2001:db8::1/128")},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeAddressRequest, typ)
	parsed, err := parseAddressRequestCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseAddressRequestCapsuleInvalid(t *testing.T) {
	testParseAddressCapsuleInvalid(t, capsuleTypeAddressRequest, func(r io.Reader) error {
		_, err := parseAddressRequestCapsule(quicvarint.NewReader(r))
		return err
	})
}

func TestParseRouteAdvertisementCapsule(t *testing.T) {
	iprange1 := []byte{4}                                                          // IPv4
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
	iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // End IP
	iprange1 = append(iprange1, 13)                                                // IP Protocol
	iprange2 := []byte{6}                                                          // IPv6
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::1").AsSlice()...)   // Start IP
	iprange2 = append(iprange2, netip.MustParseAddr("2001:db8::100").AsSlice()...) // End IP
	iprange2 = append(iprange2, 37)                                                // IP Protocol

	data := quicvarint.Append(nil, uint64(capsuleTypeRouteAdvertisement))
	data = quicvarint.Append(data, uint64(len(iprange1)+len(iprange2))) // Length
	data = append(data, iprange1...)
	data = append(data, iprange2...)

	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	capsule, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t,
		[]IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
		capsule.IPAddressRanges,
	)
	require.Equal(t,
		rangeToPrefixes(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.2.3.4")),
		capsule.IPAddressRanges[0].Prefixes(),
	)
	require.Equal(t,
		rangeToPrefixes(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::100")),
		capsule.IPAddressRanges[1].Prefixes(),
	)
	require.Zero(t, r.Len())
}

func TestWriteRouteAdvertisementCapsule(t *testing.T) {
	c := &routeAdvertisementCapsule{
		IPAddressRanges: []IPRoute{
			{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("1.2.3.4"), IPProtocol: 13},
			{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
		},
	}
	data := c.append(nil)
	r := bytes.NewReader(data)
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeRouteAdvertisement, typ)
	parsed, err := parseRouteAdvertisementCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, c, parsed)
	require.Zero(t, r.Len())
}

func TestParseRouteAdvertisementCapsuleInvalid(t *testing.T) {
	t.Run("invalid IP version", func(t *testing.T) {
		iprange1 := []byte{5}                                                          // IPv5
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 2}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol
		_, err := parseRouteAdvertisementCapsule(newCapsuleReader(t, capsuleTypeRouteAdvertisement, iprange1))
		require.ErrorContains(t, err, "invalid IP version: 5")
	})

	t.Run("start IP is greater than end IP", func(t *testing.T) {
		iprange1 := []byte{4}                                                          // IPv4
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()...) // Start IP
		iprange1 = append(iprange1, netip.AddrFrom4([4]byte{1, 1, 1, 1}).AsSlice()...) // End IP
		iprange1 = append(iprange1, 13)                                                // IP Protocol
		_, err := parseRouteAdvertisementCapsule(newCapsuleReader(t, capsuleTypeRouteAdvertisement, iprange1))
		require.ErrorContains(t, err, "start IP is greater than end IP")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		data := (&routeAdvertisementCapsule{
			IPAddressRanges: []IPRoute{
				{StartIP: netip.MustParseAddr("1.1.1.1"), EndIP: netip.MustParseAddr("2.2.2.2"), IPProtocol: 13},
				{StartIP: netip.MustParseAddr("2001:db8::1"), EndIP: netip.MustParseAddr("2001:db8::100"), IPProtocol: 37},
			},
		}).append(nil)

		testIncompleteCapsule(t, data, func(r http3.CapsuleReader) error {
			_, err := parseRouteAdvertisementCapsule(r)
			return err
		})
	})
}

func TestParseDNSAssignCapsule(t *testing.T) {
	var payload []byte
	payload = quicvarint.Append(payload, 1) // Nameserver Count
	payload = binary.BigEndian.AppendUint16(payload, 42)
	payload = quicvarint.Append(payload, 1) // IPv4 Address Count
	payload = append(payload, netip.MustParseAddr("192.0.2.33").AsSlice()...)
	payload = quicvarint.Append(payload, 1) // IPv6 Address Count
	payload = append(payload, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	payload = appendDomain(payload, "resolver.example")
	serviceParameters := []byte{0, 3, 0, 2, 0x21, 0x35} // port=853
	payload = quicvarint.Append(payload, uint64(len(serviceParameters)))
	payload = append(payload, serviceParameters...)
	payload = quicvarint.Append(payload, 1) // Internal Domain Count
	payload = appendDomain(payload, "internal.example")
	payload = quicvarint.Append(payload, 2) // Search Domain Count
	payload = appendDomain(payload, "internal.example")
	payload = appendDomain(payload, "example")

	// A DNS_ASSIGN capsule can carry another configuration for a different
	// internal domain.
	payload = quicvarint.Append(payload, 1)
	payload = binary.BigEndian.AppendUint16(payload, 1)
	payload = quicvarint.Append(payload, 1)
	payload = append(payload, netip.MustParseAddr("198.51.100.53").AsSlice()...)
	payload = quicvarint.Append(payload, 0)
	payload = appendDomain(payload, "")
	payload = quicvarint.Append(payload, 0) // Service Parameters Length
	payload = quicvarint.Append(payload, 1)
	payload = appendDomain(payload, "other.example")
	payload = quicvarint.Append(payload, 0)

	capsule, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
	require.NoError(t, err)
	require.Equal(t, &dnsAssignCapsule{
		DNSConfigurations: []DNSConfiguration{
			{
				Nameservers: []DNSNameserver{{
					ServicePriority:          42,
					IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.33")},
					IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::1")},
					AuthenticationDomainName: "resolver.example",
					ServiceParameters:        serviceParameters,
				}},
				InternalDomains: []string{"internal.example"},
				SearchDomains:   []string{"internal.example", "example"},
			},
			{
				Nameservers: []DNSNameserver{{
					ServicePriority:          1,
					IPv4Addresses:            []netip.Addr{netip.MustParseAddr("198.51.100.53")},
					AuthenticationDomainName: "",
				}},
				InternalDomains: []string{"other.example"},
			},
		},
	}, capsule)
}

func TestWriteDNSAssignCapsule(t *testing.T) {
	capsule := &dnsAssignCapsule{DNSConfigurations: []DNSConfiguration{
		{
			Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				AuthenticationDomainName: "masque.example.org",
				ServiceParameters:        []byte{0, 1, 0, 3, 2, 'h', '3'},
			}},
			InternalDomains: []string{""},
		},
		{
			Nameservers: []DNSNameserver{{
				ServicePriority: 2,
				IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			}},
			InternalDomains: []string{"internal.example"},
			SearchDomains:   []string{"internal.example", "XN--BCHER-KVA.example"},
		},
	}}

	r := bytes.NewReader(capsule.append(nil))
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypeDNSAssign, typ)
	parsed, err := parseDNSAssignCapsule(cr)
	require.NoError(t, err)
	require.Equal(t, capsule, parsed)
	require.Zero(t, r.Len())
}

func TestParseDNSAssignCapsuleInvalid(t *testing.T) {
	t.Run("zero service priority", func(t *testing.T) {
		payload := quicvarint.Append(nil, 1)
		payload = append(payload, 0, 0)
		payload = quicvarint.Append(payload, 0)
		payload = quicvarint.Append(payload, 0)
		payload = appendDomain(payload, "")
		payload = quicvarint.Append(payload, 0)
		payload = quicvarint.Append(payload, 0)
		payload = quicvarint.Append(payload, 0)

		_, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
		require.ErrorContains(t, err, "service priority must not be zero")
	})

	t.Run("truncated domain", func(t *testing.T) {
		payload := quicvarint.Append(nil, 0) // Nameserver Count
		payload = quicvarint.Append(payload, 1)
		payload = quicvarint.Append(payload, 10)
		payload = append(payload, "short"...)

		_, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("domain length limit", func(t *testing.T) {
		payload := quicvarint.Append(nil, 0) // Nameserver Count
		payload = quicvarint.Append(payload, 1)
		payload = quicvarint.Append(payload, 1<<30)

		_, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
		require.ErrorContains(t, err, "domain name too long")
	})

	t.Run("domain memory limit", func(t *testing.T) {
		payload := quicvarint.Append(nil, 2)
		payload = appendDomain(payload, "")
		payload = appendDomain(payload, "")

		_, _, err := parseCounted(newCapsuleReader(t, capsuleTypeDNSAssign, payload), dnsValueOverhead, parseDomain)
		require.ErrorIs(t, err, errDNSAssignMemoryLimit)
	})

	t.Run("domain name memory limit", func(t *testing.T) {
		_, _, err := parseDomain(newCapsuleReader(t, capsuleTypeDNSAssign, appendDomain(nil, "example")), 0)
		require.ErrorIs(t, err, errDNSAssignMemoryLimit)
	})

	t.Run("configuration memory limit", func(t *testing.T) {
		var payload []byte
		for range maxDNSAssignMemory/dnsValueOverhead + 1 {
			payload = quicvarint.Append(payload, 0) // Nameserver Count
			payload = quicvarint.Append(payload, 0) // Internal Domain Count
			payload = quicvarint.Append(payload, 0) // Search Domain Count
		}

		_, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
		require.ErrorIs(t, err, errDNSAssignMemoryLimit)
		require.ErrorContains(t, err, "parsing DNS_ASSIGN configuration")
	})

	t.Run("domain must use A-label form", func(t *testing.T) {
		payload := quicvarint.Append(nil, 0) // Nameserver Count
		payload = quicvarint.Append(payload, 1)
		payload = appendDomain(payload, "bücher.example")
		payload = quicvarint.Append(payload, 0)

		_, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
		require.ErrorContains(t, err, "invalid internal domain name: must use IDNA A-label form")
	})

	t.Run("service parameters length limit", func(t *testing.T) {
		payload := quicvarint.Append(nil, 1) // Nameserver Count
		payload = binary.BigEndian.AppendUint16(payload, 1)
		payload = quicvarint.Append(payload, 0) // IPv4 Address Count
		payload = quicvarint.Append(payload, 0) // IPv6 Address Count
		payload = appendDomain(payload, "")
		payload = quicvarint.Append(payload, 1<<30)

		_, err := parseDNSAssignCapsule(newCapsuleReader(t, capsuleTypeDNSAssign, payload))
		require.ErrorContains(t, err, "service parameters too long")
	})

	t.Run("truncated service parameters", func(t *testing.T) {
		payload := quicvarint.Append(nil, 1) // Nameserver Count
		payload = binary.BigEndian.AppendUint16(payload, 1)
		payload = quicvarint.Append(payload, 0) // IPv4 Address Count
		payload = quicvarint.Append(payload, 0) // IPv6 Address Count
		payload = appendDomain(payload, "")
		payload = quicvarint.Append(payload, 10)
		payload = append(payload, "short"...)
		r := newCapsuleReader(t, capsuleTypeDNSAssign, payload)

		_, err := parseDNSAssignCapsule(r)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Equal(t, int64(len("short")), r.Remaining())
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		data := (&dnsAssignCapsule{DNSConfigurations: []DNSConfiguration{
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
		}}).append(nil)

		testIncompleteCapsule(t, data, func(r http3.CapsuleReader) error {
			_, err := parseDNSAssignCapsule(r)
			return err
		})
	})

	t.Run("service parameters memory limit", func(t *testing.T) {
		payload := binary.BigEndian.AppendUint16(nil, 1)
		payload = quicvarint.Append(payload, 0) // IPv4 Address Count
		payload = quicvarint.Append(payload, 0) // IPv6 Address Count
		payload = appendDomain(payload, "")
		payload = quicvarint.Append(payload, 1)
		payload = append(payload, 0)

		_, _, err := parseDNSNameserver(newCapsuleReader(t, capsuleTypeDNSAssign, payload), 0)
		require.ErrorIs(t, err, errDNSAssignMemoryLimit)
	})
}

func TestParsePREF64Capsule(t *testing.T) {
	data := []byte{96, 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}
	data = append(data, 32, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 1, 0, 0)

	capsule, err := parsePREF64Capsule(newCapsuleReader(t, capsuleTypePREF64, data))
	require.NoError(t, err)
	require.Equal(t, &pref64Capsule{Prefixes: []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("2001:db8:0:0:1::/32"),
	}}, capsule)
}

func TestParsePREF64CapsuleLimit(t *testing.T) {
	prefix := []byte{96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	t.Run("at limit", func(t *testing.T) {
		capsule, err := parsePREF64Capsule(newCapsuleReader(
			t, capsuleTypePREF64, bytes.Repeat(prefix, maxPREF64Prefixes),
		))
		require.NoError(t, err)
		require.Len(t, capsule.Prefixes, maxPREF64Prefixes)
	})

	t.Run("over limit", func(t *testing.T) {
		_, err := parsePREF64Capsule(newCapsuleReader(
			t, capsuleTypePREF64, bytes.Repeat(prefix, maxPREF64Prefixes+1),
		))
		require.ErrorContains(t, err, "PREF64 capsule contains too many prefixes: 257 (maximum 256)")
	})
}

func TestWritePREF64Capsule(t *testing.T) {
	capsule := &pref64Capsule{Prefixes: []netip.Prefix{
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("2001:db8:1200::/40"),
	}}
	r := bytes.NewReader(capsule.append(nil))
	typ, cr, err := http3.NewCapsuleParser(r).Next()
	require.NoError(t, err)
	require.Equal(t, capsuleTypePREF64, typ)
	parsed, err := parsePREF64Capsule(cr)
	require.NoError(t, err)
	require.Equal(t, capsule, parsed)
	require.Zero(t, r.Len())
}

func TestWriteEmptyPREF64Capsule(t *testing.T) {
	data := (&pref64Capsule{}).append(nil)
	_, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
	require.NoError(t, err)
	parsed, err := parsePREF64Capsule(cr)
	require.NoError(t, err)
	require.Empty(t, parsed.Prefixes)
}

func TestParsePREF64CapsuleInvalid(t *testing.T) {
	t.Run("invalid prefix length", func(t *testing.T) {
		_, err := parsePREF64Capsule(newCapsuleReader(t, capsuleTypePREF64, make([]byte, 13)))
		require.ErrorContains(t, err, "invalid NAT64 prefix length: 0")
	})

	t.Run("IPv4-mapped IPv6 prefix", func(t *testing.T) {
		data := []byte{96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
		_, err := parsePREF64Capsule(newCapsuleReader(t, capsuleTypePREF64, data))
		require.ErrorContains(t, err, "IPv4-mapped IPv6 addresses are not valid NAT64 prefixes")
	})

	t.Run("length not a multiple of 13", func(t *testing.T) {
		_, err := parsePREF64Capsule(newCapsuleReader(t, capsuleTypePREF64, make([]byte, 12)))
		require.ErrorContains(t, err, "length is not a multiple of 13")
	})

	t.Run("incomplete capsule", func(t *testing.T) {
		data := (&pref64Capsule{Prefixes: []netip.Prefix{
			netip.MustParsePrefix("64:ff9b::/96"),
			netip.MustParsePrefix("2001:db8::/32"),
		}}).append(nil)

		testIncompleteCapsule(t, data, func(r http3.CapsuleReader) error {
			_, err := parsePREF64Capsule(r)
			return err
		})
	})
}
