package connectip

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const (
	// RFC 1035, Section 2.3.4 limits a domain name to 255 octets.
	maxDomainNameLen = 255
	// SvcParams use DNS RDATA encoding, whose RDLENGTH field is 16 bits
	// (RFC 1035, Section 4.1.3).
	maxServiceParametersLen = 1<<16 - 1
)

// DNSNameserver describes the Nameserver structure defined by
// draft-ietf-masque-connect-ip-dns-06. ServiceParameters contains SvcParams
// in the wire format defined by RFC 9460.
type DNSNameserver struct {
	ServicePriority uint16
	IPv4Addresses   []netip.Addr
	IPv6Addresses   []netip.Addr
	// AuthenticationDomainName is the fully qualified domain name of the
	// nameserver. It must be in DNS presentation format using IDNA A-labels;
	// U-labels are rejected. It may be empty only when the nameserver supports
	// unencrypted DNS exclusively.
	AuthenticationDomainName string
	ServiceParameters        []byte
}

// DNSConfiguration describes the DNS Configuration structure defined by
// draft-ietf-masque-connect-ip-dns-06.
type DNSConfiguration struct {
	Nameservers []DNSNameserver
	// InternalDomains contains fully qualified domain names in DNS presentation
	// format using IDNA A-labels. U-labels are rejected. An empty string
	// represents the DNS root.
	InternalDomains []string
	// SearchDomains contains fully qualified domain names in DNS presentation
	// format using IDNA A-labels. U-labels and empty strings are rejected.
	SearchDomains []string
}

var dnsNameProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
)

func validateDomainName(name string, allowEmpty bool) error {
	if name == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("must not be empty")
	}
	for i := range len(name) {
		if name[i] >= utf8.RuneSelf {
			return errors.New("must use IDNA A-label form")
		}
	}
	ascii, err := dnsNameProfile.ToASCII(name)
	if err != nil {
		return fmt.Errorf("must be a valid IDNA A-label: %w", err)
	}
	if !strings.EqualFold(ascii, name) {
		return errors.New("must use IDNA A-label form")
	}
	return nil
}

func (c DNSConfiguration) validate() error {
	for _, nameserver := range c.Nameservers {
		if nameserver.ServicePriority == 0 {
			return errors.New("service priority must not be zero")
		}
		if len(nameserver.ServiceParameters) > maxServiceParametersLen {
			return errors.New("service parameters too long")
		}
		if err := validateDomainName(nameserver.AuthenticationDomainName, true); err != nil {
			return fmt.Errorf("invalid authentication domain name: %w", err)
		}
		for _, addr := range nameserver.IPv4Addresses {
			if !addr.Is4() {
				return fmt.Errorf("non-IPv4 address in IPv4 address list: %s", addr)
			}
		}
		for _, addr := range nameserver.IPv6Addresses {
			if !addr.Is6() || addr.Is4In6() {
				return fmt.Errorf("non-IPv6 address in IPv6 address list: %s", addr)
			}
		}
	}
	for _, domain := range c.InternalDomains {
		if err := validateDomainName(domain, true); err != nil {
			return fmt.Errorf("invalid internal domain name: %w", err)
		}
	}
	for _, domain := range c.SearchDomains {
		if err := validateDomainName(domain, false); err != nil {
			return fmt.Errorf("invalid search domain name: %w", err)
		}
	}
	return nil
}
