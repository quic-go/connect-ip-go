package connectip

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"
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
// draft-ietf-masque-connect-ip-dns-06.
type DNSNameserver struct {
	ServicePriority uint16
	IPv4Addresses   []netip.Addr
	// IPv6Addresses must not contain scoped addressing zones.
	// Zone identifiers are local to an endpoint and are not part of the wire format.
	IPv6Addresses []netip.Addr
	// AuthenticationDomainName is the fully qualified domain name of the
	// nameserver. It must be in DNS presentation format, including the terminating
	// root dot, and use IDNA A-labels; U-labels are rejected. It may be empty only
	// when the nameserver supports unencrypted DNS exclusively.
	AuthenticationDomainName string
	// ServiceParameters is the set of SVCB parameters that apply to this nameserver.
	// Each map value is the wire-format SvcParamValue for its key.
	ServiceParameters map[dnsmessage.SVCParamKey][]byte
}

// DNSConfiguration describes the DNS Configuration structure defined by
// draft-ietf-masque-connect-ip-dns-06.
type DNSConfiguration struct {
	Nameservers []DNSNameserver
	// InternalDomains contains fully qualified domain names in DNS presentation
	// format, including the terminating root dot, using IDNA A-labels. U-labels
	// are rejected. An empty string represents the DNS root.
	InternalDomains []string
	// SearchDomains contains fully qualified domain names in DNS presentation
	// format, including the terminating root dot, using IDNA A-labels. U-labels
	// and empty strings are rejected.
	SearchDomains []string
}

var dnsNameProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
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
	name, ok := strings.CutSuffix(name, ".")
	if !ok {
		return errors.New("must be an FQDN")
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
	for _, ns := range c.Nameservers {
		if ns.ServicePriority == 0 {
			return errors.New("service priority must not be zero")
		}
		var serviceParametersLen int
		var hasALPN, hasNoDefaultALPN bool
		for k, v := range ns.ServiceParameters {
			if len(v) > maxServiceParametersLen {
				return errors.New("service parameter value too long")
			}
			serviceParametersLen += 4 + len(v)
			switch k {
			case dnsmessage.SVCParamALPN:
				hasALPN = true
			case dnsmessage.SVCParamNoDefaultALPN:
				hasNoDefaultALPN = true
			case dnsmessage.SVCParamIPv4Hint, dnsmessage.SVCParamIPv6Hint:
				return fmt.Errorf("service parameter %s is not allowed", k)
			}
		}
		if serviceParametersLen > maxServiceParametersLen {
			return errors.New("service parameters too long")
		}
		if err := validateDomainName(ns.AuthenticationDomainName, true); err != nil {
			return fmt.Errorf("invalid authentication domain name: %w", err)
		}
		if ns.AuthenticationDomainName == "" && (hasALPN || hasNoDefaultALPN) {
			return errors.New("ALPN service parameters require an authentication domain name")
		}
		if !hasNoDefaultALPN && len(ns.IPv4Addresses)+len(ns.IPv6Addresses) == 0 {
			return errors.New("nameserver must have an address when no-default-alpn is omitted")
		}
		for _, addr := range ns.IPv4Addresses {
			if !addr.Is4() {
				return fmt.Errorf("non-IPv4 address in IPv4 address list: %s", addr)
			}
		}
		for _, addr := range ns.IPv6Addresses {
			if !addr.Is6() || addr.Is4In6() {
				return fmt.Errorf("non-IPv6 address in IPv6 address list: %s", addr)
			}
			if addr.Zone() != "" {
				return fmt.Errorf("IPv6 address with zone in IPv6 address list: %s", addr)
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
