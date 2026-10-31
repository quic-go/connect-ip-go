package qlog

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"

	"github.com/stretchr/testify/require"
)

func check(t *testing.T, c any, expected string) {
	t.Helper()

	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	require.NoError(t, (Capsule{Capsule: c}).encode(enc))
	require.JSONEq(t, expected, buf.String())
}

func TestAddressAssignCapsule(t *testing.T) {
	check(t, AddressAssignCapsule{
		AssignedAddresses: []Address{
			{RequestID: 0, IPPrefix: netip.MustParsePrefix("192.0.2.0/24")},
			{RequestID: 1337, IPPrefix: netip.MustParsePrefix("2001:db8::/64")},
			{RequestID: 42, IPPrefix: netip.MustParsePrefix("::/128")},
		},
		Raw: RawInfo{Length: 50, PayloadLength: 48},
	}, `{
		"capsule_type": "address_assign",
		"assigned_addresses": [
			{"request_id": 0, "ip_prefix": "192.0.2.0/24"},
			{"request_id": 1337, "ip_prefix": "2001:db8::/64"},
			{"request_id": 42, "ip_prefix": "::/128"}
		],
		"raw": {"length": 50, "payload_length": 48}
	}`)
}

func TestAddressAssignCapsuleEmpty(t *testing.T) {
	check(t, AddressAssignCapsule{
		Raw: RawInfo{Length: OmitLength, PayloadLength: OmitLength},
	}, `{
		"capsule_type": "address_assign",
		"assigned_addresses": []
	}`)
}

func TestAddressRequestCapsule(t *testing.T) {
	check(t, AddressRequestCapsule{
		RequestedAddresses: []Address{
			{RequestID: 1, IPPrefix: netip.MustParsePrefix("0.0.0.0/32")},
			{RequestID: 2, IPPrefix: netip.MustParsePrefix("2001:db8::/56")},
		},
		Raw: RawInfo{Length: 28, PayloadLength: 26},
	}, `{
		"capsule_type": "address_request",
		"requested_addresses": [
			{"request_id": 1, "ip_prefix": "0.0.0.0/32"},
			{"request_id": 2, "ip_prefix": "2001:db8::/56"}
		],
		"raw": {"length": 28, "payload_length": 26}
	}`)
}

func TestRouteAdvertisementCapsule(t *testing.T) {
	check(t, RouteAdvertisementCapsule{
		IPAddressRanges: []IPAddressRange{
			{StartIP: netip.MustParseAddr("192.0.2.0"), EndIP: netip.MustParseAddr("192.0.2.255")},
			{StartIP: netip.MustParseAddr("2001:db8::"), EndIP: netip.MustParseAddr("2001:db8::ffff"), IPProtocol: 17},
		},
		Raw: RawInfo{Length: 46, PayloadLength: 44},
	}, `{
		"capsule_type": "route_advertisement",
		"ip_address_ranges": [
			{"start_ip": "192.0.2.0", "end_ip": "192.0.2.255", "ip_protocol": 0},
			{"start_ip": "2001:db8::", "end_ip": "2001:db8::ffff", "ip_protocol": 17}
		],
		"raw": {"length": 46, "payload_length": 44}
	}`)
}

func TestRouteAdvertisementCapsuleEmpty(t *testing.T) {
	check(t, RouteAdvertisementCapsule{
		Raw: RawInfo{Length: 2, PayloadLength: 0},
	}, `{
		"capsule_type": "route_advertisement",
		"ip_address_ranges": [],
		"raw": {"length": 2, "payload_length": 0}
	}`)
}

func TestDNSAssignCapsule(t *testing.T) {
	check(t, DNSAssignCapsule{
		DNSConfigurations: []DNSConfiguration{
			{
				Nameservers: []DNSNameserver{
					{
						ServicePriority:          1,
						IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.53")},
						IPv6Addresses:            []netip.Addr{netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("2001:db8::54")},
						AuthenticationDomainName: "dns.example",
						ServiceParameters: []DNSServiceParameter{
							{Key: 1, Value: []byte("\x03dot")},
							{Key: 2},
							{Key: 3, Value: []byte{0x03, 0x55}},
						},
					},
					{ServicePriority: 2, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.54")}},
				},
				InternalDomains: []string{"example", ""},
				SearchDomains:   []string{"corp.example"},
			},
			{
				Nameservers: []DNSNameserver{{ServicePriority: 1, IPv6Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::35")}}},
			},
		},
		Raw: RawInfo{Length: 1000, PayloadLength: 990},
	}, `{
		"capsule_type": "dns_assign",
		"dns_configurations": [
			{
				"nameservers": [
					{
						"service_priority": 1,
						"ipv4_addresses": ["192.0.2.53"],
						"ipv6_addresses": ["2001:db8::53", "2001:db8::54"],
						"authentication_domain_name": "dns.example",
						"service_parameters": [
							{"key": 1, "value": "03646f74"},
							{"key": 2, "value": ""},
							{"key": 3, "value": "0355"}
						]
					},
					{
						"service_priority": 2,
						"ipv4_addresses": ["192.0.2.54"],
						"ipv6_addresses": [],
						"authentication_domain_name": "",
						"service_parameters": []
					}
				],
				"internal_domains": ["example", ""],
				"search_domains": ["corp.example"]
			},
			{
				"nameservers": [
					{
						"service_priority": 1,
						"ipv4_addresses": [],
						"ipv6_addresses": ["2001:db8::35"],
						"authentication_domain_name": "",
						"service_parameters": []
					}
				],
				"internal_domains": [],
				"search_domains": []
			}
		],
		"raw": {"length": 1000, "payload_length": 990}
	}`)
}

func TestPREF64Capsule(t *testing.T) {
	check(t, PREF64Capsule{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("2001:db8:100::/40")},
		Raw:      RawInfo{Length: 31, PayloadLength: 26},
	}, `{
		"capsule_type": "pref64",
		"prefixes": ["64:ff9b::/96", "2001:db8:100::/40"],
		"raw": {"length": 31, "payload_length": 26}
	}`)
}

func TestPREF64CapsuleEmpty(t *testing.T) {
	check(t, PREF64Capsule{
		Raw: RawInfo{Length: OmitLength, PayloadLength: OmitLength},
	}, `{
		"capsule_type": "pref64",
		"prefixes": []
	}`)
}

func TestUnknownCapsule(t *testing.T) {
	check(t, UnknownCapsule{
		Type: 0x1337,
		Raw:  RawInfo{Length: 13, PayloadLength: 10},
	}, `{
		"capsule_type": "unknown",
		"capsule_type_value": 4919,
		"raw": {"length": 13, "payload_length": 10}
	}`)
}
