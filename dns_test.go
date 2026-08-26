package connectip

import (
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
				Nameservers:     []DNSNameserver{{ServicePriority: 1}},
				InternalDomains: []string{""},
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
				Nameservers:     []DNSNameserver{{ServicePriority: 1}},
				InternalDomains: []string{"bücher.example"},
			},
			err: "invalid internal domain name: must use IDNA A-label form",
		},
		{
			name: "search U-label",
			configuration: DNSConfiguration{
				Nameservers:   []DNSNameserver{{ServicePriority: 1}},
				SearchDomains: []string{"bücher.example"},
			},
			err: "invalid search domain name: must use IDNA A-label form",
		},
		{
			name: "empty search domain",
			configuration: DNSConfiguration{
				Nameservers:   []DNSNameserver{{ServicePriority: 1}},
				SearchDomains: []string{""},
			},
			err: "invalid search domain name: must not be empty",
		},
		{
			name: "invalid A-label",
			configuration: DNSConfiguration{
				Nameservers:   []DNSNameserver{{ServicePriority: 1}},
				SearchDomains: []string{"xn--.example"},
			},
			err: "invalid search domain name: must be a valid IDNA A-label",
		},
		{
			name: "label too long",
			configuration: DNSConfiguration{
				Nameservers:   []DNSNameserver{{ServicePriority: 1}},
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
