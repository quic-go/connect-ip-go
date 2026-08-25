package connectip

import (
	"errors"
	"fmt"
	"net/netip"
)

const (
	// RFC 1035, Section 2.3.4 limits a domain name to 255 octets.
	maxDomainNameLen = 255
	// SvcParams use DNS RDATA encoding, whose RDLENGTH field is 16 bits
	// (RFC 1035, Section 4.1.3).
	maxServiceParametersLen = 1<<16 - 1
)

// DNSNameserver describes the Nameserver structure defined in Section 3.2 of
// draft-ietf-masque-connect-ip-dns-06. ServiceParameters contains SvcParams in
// the wire format defined by RFC 9460.
type DNSNameserver struct {
	ServicePriority          uint16
	IPv4Addresses            []netip.Addr
	IPv6Addresses            []netip.Addr
	AuthenticationDomainName string
	ServiceParameters        []byte
}

// DNSConfiguration describes the DNS Configuration structure defined in
// Section 3.3 of draft-ietf-masque-connect-ip-dns-06. An empty internal domain
// represents the DNS root.
type DNSConfiguration struct {
	Nameservers     []DNSNameserver
	InternalDomains []string
	SearchDomains   []string
}

func (c DNSConfiguration) validate() error {
	for _, nameserver := range c.Nameservers {
		switch {
		case nameserver.ServicePriority == 0:
			return errors.New("service priority must not be zero")
		case len(nameserver.AuthenticationDomainName) > maxDomainNameLen:
			return errors.New("authentication domain name too long")
		case len(nameserver.ServiceParameters) > maxServiceParametersLen:
			return errors.New("service parameters too long")
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
		if len(domain) > maxDomainNameLen {
			return errors.New("internal domain name too long")
		}
	}
	for _, domain := range c.SearchDomains {
		if len(domain) > maxDomainNameLen {
			return errors.New("search domain name too long")
		}
	}
	return nil
}
