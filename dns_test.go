package connectip

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
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
					IPv4Addresses:            []netip.Addr{netip.MustParseAddr("192.0.2.53")},
					AuthenticationDomainName: "xn--bcher-kva.example.",
				}},
				InternalDomains: []string{"xn--bcher-kva.internal.example."},
				SearchDomains:   []string{"XN--BCHER-KVA.example."},
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
				SearchDomains: []string{"_msdcs.corp.example."},
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
				AuthenticationDomainName: "bücher.example.",
			}}},
			err: "invalid authentication domain name: must use IDNA A-label form",
		},
		{
			name: "internal U-label",
			configuration: DNSConfiguration{
				InternalDomains: []string{"bücher.example."},
			},
			err: "invalid internal domain name: must use IDNA A-label form",
		},
		{
			name: "search U-label",
			configuration: DNSConfiguration{
				SearchDomains: []string{"bücher.example."},
			},
			err: "invalid search domain name: must use IDNA A-label form",
		},
		{
			name: "authentication domain must be an FQDN",
			configuration: DNSConfiguration{Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				AuthenticationDomainName: "resolver.example",
			}}},
			err: "invalid authentication domain name: must be an FQDN",
		},
		{
			name: "internal domain must be an FQDN",
			configuration: DNSConfiguration{
				InternalDomains: []string{"internal.example"},
			},
			err: "invalid internal domain name: must be an FQDN",
		},
		{
			name: "search domain must be an FQDN",
			configuration: DNSConfiguration{
				SearchDomains: []string{"example"},
			},
			err: "invalid search domain name: must be an FQDN",
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
				SearchDomains: []string{"xn--.example."},
			},
			err: "invalid search domain name: must be a valid IDNA A-label",
		},
		{
			name: "leading hyphen",
			configuration: DNSConfiguration{
				SearchDomains: []string{"-resolver.example."},
			},
			err: "invalid search domain name: must be a valid IDNA A-label",
		},
		{
			name: "label too long",
			configuration: DNSConfiguration{
				SearchDomains: []string{strings.Repeat("a", 64) + ".example."},
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

func TestDNSConfigurationValidServiceParameters(t *testing.T) {
	alpn := []byte{2, 'h', '2', 2, 'h', '3'}
	tests := []struct {
		name              string
		serviceParameters map[dnsmessage.SVCParamKey][]byte
	}{
		{
			name: "encrypted DNS without an address",
			serviceParameters: map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamALPN:          alpn,
				dnsmessage.SVCParamNoDefaultALPN: {},
			},
		},
		{
			name: "opaque no-default-alpn value",
			serviceParameters: map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamALPN:          alpn,
				dnsmessage.SVCParamNoDefaultALPN: {1},
			},
		},
		{
			name:              "no-default-alpn without ALPN",
			serviceParameters: map[dnsmessage.SVCParamKey][]byte{dnsmessage.SVCParamNoDefaultALPN: {}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := DNSConfiguration{Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				AuthenticationDomainName: "resolver.example.",
				ServiceParameters:        test.serviceParameters,
			}}}
			require.NoError(t, configuration.validate())
		})
	}
}

func TestDNSConfigurationInvalidServiceParameters(t *testing.T) {
	alpn := []byte{2, 'h', '2', 2, 'h', '3'}
	tests := []struct {
		name                     string
		authenticationDomainName string
		ipv4Addresses            []netip.Addr
		serviceParameters        map[dnsmessage.SVCParamKey][]byte
		err                      string
	}{
		{
			name:                     "parameters too long",
			authenticationDomainName: "resolver.example.",
			serviceParameters: map[dnsmessage.SVCParamKey][]byte{
				dnsmessage.SVCParamPort: make([]byte, maxServiceParametersLen),
			},
			err: "service parameters too long",
		},
		{
			name:                     "IPv4 hint",
			authenticationDomainName: "resolver.example.",
			serviceParameters:        map[dnsmessage.SVCParamKey][]byte{dnsmessage.SVCParamIPv4Hint: nil},
			err:                      "service parameter IPv4Hint is not allowed",
		},
		{
			name:                     "IPv6 hint",
			authenticationDomainName: "resolver.example.",
			serviceParameters:        map[dnsmessage.SVCParamKey][]byte{dnsmessage.SVCParamIPv6Hint: nil},
			err:                      "service parameter IPv6Hint is not allowed",
		},
		{
			name:              "ALPN without authentication domain name",
			ipv4Addresses:     []netip.Addr{netip.MustParseAddr("192.0.2.53")},
			serviceParameters: map[dnsmessage.SVCParamKey][]byte{dnsmessage.SVCParamALPN: alpn},
			err:               "ALPN service parameters require an authentication domain name",
		},
		{
			name:                     "unencrypted DNS without an address",
			authenticationDomainName: "resolver.example.",
			err:                      "nameserver must have an address when no-default-alpn is omitted",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := DNSConfiguration{Nameservers: []DNSNameserver{{
				ServicePriority:          1,
				IPv4Addresses:            test.ipv4Addresses,
				AuthenticationDomainName: test.authenticationDomainName,
				ServiceParameters:        test.serviceParameters,
			}}}
			require.ErrorContains(t, configuration.validate(), test.err)
		})
	}
}
