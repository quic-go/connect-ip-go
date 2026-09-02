package connectip

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDNSConfigurationDomainValidation(t *testing.T) {
	tests := []struct {
		name          string
		configuration DNSConfiguration
		err           string
	}{
		{
			name: "A-labels",
			configuration: DNSConfiguration{
				Nameservers: []DNSNameserver{{
					ServicePriority:          1,
					AuthenticationDomainName: "xn--bcher-kva.example",
				}},
				InternalDomains: []string{"xn--bcher-kva.internal.example"},
				SearchDomains:   []string{"XN--BCHER-KVA.example"},
			},
		},
		{
			name: "empty authentication and internal domains",
			configuration: DNSConfiguration{
				Nameservers: []DNSNameserver{{
					ServicePriority: 1,
					IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.53")},
				}},
				InternalDomains: []string{""},
			},
		},
		{
			name: "underscore label",
			configuration: DNSConfiguration{
				SearchDomains: []string{"_msdcs.corp.example"},
			},
		},
		{
			name: "trailing root dot",
			configuration: DNSConfiguration{
				SearchDomains: []string{"example.com."},
			},
		},
		{
			name: "authentication U-label",
			configuration: DNSConfiguration{Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				AuthenticationDomainName: "bücher.example",
			}}},
			err: "invalid authentication domain name: must use IDNA A-label form",
		},
		{
			name: "internal U-label",
			configuration: DNSConfiguration{
				InternalDomains: []string{"bücher.example"},
			},
			err: "invalid internal domain name: must use IDNA A-label form",
		},
		{
			name: "search U-label",
			configuration: DNSConfiguration{
				SearchDomains: []string{"bücher.example"},
			},
			err: "invalid search domain name: must use IDNA A-label form",
		},
		{
			name: "empty search domain",
			configuration: DNSConfiguration{
				SearchDomains: []string{""},
			},
			err: "invalid search domain name: must not be empty",
		},
		{
			name: "invalid A-label",
			configuration: DNSConfiguration{
				SearchDomains: []string{"xn--.example"},
			},
			err: "invalid search domain name: must be a valid IDNA A-label",
		},
		{
			name: "leading hyphen",
			configuration: DNSConfiguration{
				SearchDomains: []string{"-resolver.example"},
			},
			err: "invalid search domain name: must be a valid IDNA A-label",
		},
		{
			name: "label too long",
			configuration: DNSConfiguration{
				SearchDomains: []string{strings.Repeat("a", 64) + ".example"},
			},
			err: "invalid search domain name: must be a valid IDNA A-label",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.configuration.validate()
			if test.err == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.err)
		})
	}
}

func TestDNSConfigurationNameserverAddressValidation(t *testing.T) {
	t.Run("no address", func(t *testing.T) {
		configuration := DNSConfiguration{Nameservers: []DNSNameserver{{ServicePriority: 1}}}
		require.ErrorContains(t, configuration.validate(), "nameserver must have an address")
	})

	t.Run("IPv4 address", func(t *testing.T) {
		configuration := DNSConfiguration{Nameservers: []DNSNameserver{{
			ServicePriority: 1,
			IPv4Addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		}}}
		require.NoError(t, configuration.validate())
	})

	t.Run("IPv6 address", func(t *testing.T) {
		configuration := DNSConfiguration{Nameservers: []DNSNameserver{{
			ServicePriority: 1,
			IPv6Addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::53")},
		}}}
		require.NoError(t, configuration.validate())
	})
}

func TestDNSConfigurationIPv6ZoneValidation(t *testing.T) {
	t.Run("link-local address without zone", func(t *testing.T) {
		configuration := DNSConfiguration{Nameservers: []DNSNameserver{{
			ServicePriority: 1,
			IPv6Addresses:   []netip.Addr{netip.MustParseAddr("fe80::1")},
		}}}
		require.NoError(t, configuration.validate())
	})

	t.Run("link-local address with zone", func(t *testing.T) {
		configuration := DNSConfiguration{Nameservers: []DNSNameserver{{
			ServicePriority: 1,
			IPv6Addresses:   []netip.Addr{netip.MustParseAddr("fe80::1%eth0")},
		}}}
		require.ErrorContains(t, configuration.validate(), "IPv6 address with zone")
	})
}
