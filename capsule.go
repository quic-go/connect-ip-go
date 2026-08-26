package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	capsuleTypeAddressAssign      http3.CapsuleType = 1
	capsuleTypeAddressRequest     http3.CapsuleType = 2
	capsuleTypeRouteAdvertisement http3.CapsuleType = 3
	// draft-ietf-masque-connect-ip-dns-06
	capsuleTypeDNSAssign http3.CapsuleType = 0x1ace79ec
	capsuleTypePREF64    http3.CapsuleType = 0x274c0fbc
)

// addressAssignCapsule represents an ADDRESS_ASSIGN capsule
type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

// AssignedAddress represents an Assigned Address within an ADDRESS_ASSIGN capsule
type AssignedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (a AssignedAddress) len() int {
	return quicvarint.Len(a.RequestID) + 1 + a.IPPrefix.Addr().BitLen()/8 + 1
}

// addressRequestCapsule represents an ADDRESS_REQUEST capsule
type addressRequestCapsule struct {
	RequestedAddresses []RequestedAddress
}

// RequestedAddress represents an Requested Address within an ADDRESS_REQUEST capsule
type RequestedAddress struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (r RequestedAddress) len() int {
	return quicvarint.Len(r.RequestID) + 1 + r.IPPrefix.Addr().BitLen()/8 + 1
}

func parseAddressAssignCapsule(r io.Reader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for {
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, AssignedAddress{RequestID: requestID, IPPrefix: prefix})
	}
	return &addressAssignCapsule{AssignedAddresses: assignedAddresses}, nil
}

func (c *addressAssignCapsule) append(b []byte) []byte {
	totalLen := 0
	for _, addr := range c.AssignedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressAssign))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.AssignedAddresses {
		b = quicvarint.Append(b, addr.RequestID)
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddressRequestCapsule(r io.Reader) (*addressRequestCapsule, error) {
	var requestedAddresses []RequestedAddress
	for {
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		requestedAddresses = append(requestedAddresses, RequestedAddress{RequestID: requestID, IPPrefix: prefix})
	}
	return &addressRequestCapsule{RequestedAddresses: requestedAddresses}, nil
}

func (c *addressRequestCapsule) append(b []byte) []byte {
	var totalLen int
	for _, addr := range c.RequestedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressRequest))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.RequestedAddresses {
		b = quicvarint.Append(b, addr.RequestID)
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddress(r io.Reader) (requestID uint64, prefix netip.Prefix, _ error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	var ip netip.Addr
	switch ipVersion {
	case 4:
		var ipv4 [4]byte
		if _, err := io.ReadFull(r, ipv4[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom4(ipv4)
	case 6:
		var ipv6 [16]byte
		if _, err := io.ReadFull(r, ipv6[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom16(ipv6)
	default:
		return 0, netip.Prefix{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixLen, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	if int(prefixLen) > ip.BitLen() {
		return 0, netip.Prefix{}, fmt.Errorf("prefix length %d exceeds IP address length (%d)", prefixLen, ip.BitLen())
	}
	prefix = netip.PrefixFrom(ip, int(prefixLen))
	if prefix != prefix.Masked() {
		return 0, netip.Prefix{}, errors.New("lower bits not covered by prefix length are not all zero")
	}
	return requestID, prefix, nil
}

// routeAdvertisementCapsule represents a ROUTE_ADVERTISEMENT capsule
type routeAdvertisementCapsule struct {
	IPAddressRanges []IPRoute
}

// IPRoute represents an IP Address Range
type IPRoute struct {
	StartIP netip.Addr
	EndIP   netip.Addr
	// IPProtocol is the Internet Protocol Number for traffic that can be sent to this range.
	// If the value is 0, all protocols are allowed.
	IPProtocol uint8
}

func (r IPRoute) len() int { return 1 + r.StartIP.BitLen()/8 + r.EndIP.BitLen()/8 + 1 }

// Prefixes returns the prefixes that this IP address range covers.
// Note that depending on the start and end addresses,
// this conversion can result in a large number of prefixes.
func (r IPRoute) Prefixes() []netip.Prefix { return rangeToPrefixes(r.StartIP, r.EndIP) }

func parseRouteAdvertisementCapsule(r io.Reader) (*routeAdvertisementCapsule, error) {
	var ranges []IPRoute
	for {
		ipRange, err := parseIPAddressRange(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ranges = append(ranges, ipRange)
	}
	return &routeAdvertisementCapsule{IPAddressRanges: ranges}, nil
}

func (c *routeAdvertisementCapsule) append(b []byte) []byte {
	var totalLen int
	for _, ipRange := range c.IPAddressRanges {
		totalLen += ipRange.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeRouteAdvertisement))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, ipRange := range c.IPAddressRanges {
		if ipRange.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, ipRange.StartIP.AsSlice()...)
		b = append(b, ipRange.EndIP.AsSlice()...)
		b = append(b, ipRange.IPProtocol)
	}
	return b
}

func parseIPAddressRange(r io.Reader) (IPRoute, error) {
	var ipVersion uint8
	if err := binary.Read(r, binary.LittleEndian, &ipVersion); err != nil {
		return IPRoute{}, err
	}

	var startIP, endIP netip.Addr
	switch ipVersion {
	case 4:
		var start, end [4]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom4(start)
		endIP = netip.AddrFrom4(end)
	case 6:
		var start, end [16]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom16(start)
		endIP = netip.AddrFrom16(end)
	default:
		return IPRoute{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}

	if startIP.Compare(endIP) > 0 {
		return IPRoute{}, errors.New("start IP is greater than end IP")
	}

	var ipProtocol uint8
	if err := binary.Read(r, binary.LittleEndian, &ipProtocol); err != nil {
		return IPRoute{}, err
	}
	return IPRoute{
		StartIP:    startIP,
		EndIP:      endIP,
		IPProtocol: ipProtocol,
	}, nil
}

// dnsAssignCapsule represents a DNS_ASSIGN capsule defined by
// draft-ietf-masque-connect-ip-dns-06.
type dnsAssignCapsule struct {
	DNSConfigurations []DNSConfiguration
}

func parseCounted[T any](r quicvarint.Reader, parse func(quicvarint.Reader) (T, error)) ([]T, error) {
	count, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	var values []T
	for range count {
		value, err := parse(r)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func parseDNSAssignCapsule(r http3.CapsuleReader) (*dnsAssignCapsule, error) {
	var configurations []DNSConfiguration
	for r.Remaining() > 0 {
		nameservers, err := parseCounted(r, parseDNSNameserver)
		if err != nil {
			return nil, err
		}
		internalDomains, err := parseCounted(r, parseDomain)
		if err != nil {
			return nil, err
		}
		searchDomains, err := parseCounted(r, parseDomain)
		if err != nil {
			return nil, err
		}
		configuration := DNSConfiguration{
			Nameservers:     nameservers,
			InternalDomains: internalDomains,
			SearchDomains:   searchDomains,
		}
		if err := configuration.validate(); err != nil {
			return nil, fmt.Errorf("invalid DNS configuration: %w", err)
		}
		configurations = append(configurations, configuration)
	}
	return &dnsAssignCapsule{DNSConfigurations: configurations}, nil
}

func parseDNSNameserver(r quicvarint.Reader) (DNSNameserver, error) {
	var priorityBytes [2]byte
	if _, err := io.ReadFull(r, priorityBytes[:]); err != nil {
		return DNSNameserver{}, err
	}
	servicePriority := binary.BigEndian.Uint16(priorityBytes[:])
	ipv4Count, err := quicvarint.Read(r)
	if err != nil {
		return DNSNameserver{}, err
	}
	var ipv4Addresses []netip.Addr
	for range ipv4Count {
		var addr [4]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return DNSNameserver{}, err
		}
		ipv4Addresses = append(ipv4Addresses, netip.AddrFrom4(addr))
	}

	ipv6Count, err := quicvarint.Read(r)
	if err != nil {
		return DNSNameserver{}, err
	}
	var ipv6Addresses []netip.Addr
	for range ipv6Count {
		var addr [16]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return DNSNameserver{}, err
		}
		ipv6Addresses = append(ipv6Addresses, netip.AddrFrom16(addr))
	}

	authenticationDomainName, err := parseDomain(r)
	if err != nil {
		return DNSNameserver{}, err
	}
	paramsLen, err := quicvarint.Read(r)
	if err != nil {
		return DNSNameserver{}, err
	}
	if paramsLen > maxServiceParametersLen {
		return DNSNameserver{}, fmt.Errorf("service parameters too long: %d bytes", paramsLen)
	}
	var serviceParameters []byte
	if paramsLen > 0 {
		serviceParameters = make([]byte, int(paramsLen))
		if _, err := io.ReadFull(r, serviceParameters); err != nil {
			return DNSNameserver{}, err
		}
	}
	return DNSNameserver{
		ServicePriority:          servicePriority,
		IPv4Addresses:            ipv4Addresses,
		IPv6Addresses:            ipv6Addresses,
		AuthenticationDomainName: authenticationDomainName,
		ServiceParameters:        serviceParameters,
	}, nil
}

func parseDomain(r quicvarint.Reader) (string, error) {
	l, err := quicvarint.Read(r)
	if err != nil {
		return "", err
	}
	if l > maxDomainNameLen {
		return "", fmt.Errorf("domain name too long: %d bytes", l)
	}
	if l == 0 {
		return "", nil
	}
	b := make([]byte, int(l))
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *dnsAssignCapsule) append(b []byte) []byte {
	payload := make([]byte, 0, 256)
	for _, cfg := range c.DNSConfigurations {
		payload = quicvarint.Append(payload, uint64(len(cfg.Nameservers)))
		for _, nameserver := range cfg.Nameservers {
			payload = binary.BigEndian.AppendUint16(payload, nameserver.ServicePriority)
			payload = quicvarint.Append(payload, uint64(len(nameserver.IPv4Addresses)))
			for _, addr := range nameserver.IPv4Addresses {
				payload = append(payload, addr.AsSlice()...)
			}
			payload = quicvarint.Append(payload, uint64(len(nameserver.IPv6Addresses)))
			for _, addr := range nameserver.IPv6Addresses {
				payload = append(payload, addr.AsSlice()...)
			}
			payload = appendDomain(payload, nameserver.AuthenticationDomainName)
			payload = quicvarint.Append(payload, uint64(len(nameserver.ServiceParameters)))
			payload = append(payload, nameserver.ServiceParameters...)
		}
		payload = quicvarint.Append(payload, uint64(len(cfg.InternalDomains)))
		for _, domain := range cfg.InternalDomains {
			payload = appendDomain(payload, domain)
		}
		payload = quicvarint.Append(payload, uint64(len(cfg.SearchDomains)))
		for _, domain := range cfg.SearchDomains {
			payload = appendDomain(payload, domain)
		}
	}
	b = quicvarint.Append(b, uint64(capsuleTypeDNSAssign))
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

func appendDomain(b []byte, domain string) []byte {
	b = quicvarint.Append(b, uint64(len(domain)))
	return append(b, domain...)
}

// pref64Capsule represents a PREF64 capsule defined by
// draft-ietf-masque-connect-ip-dns-06.
type pref64Capsule struct {
	Prefixes []netip.Prefix
}

func parsePREF64Capsule(r http3.CapsuleReader) (*pref64Capsule, error) {
	if r.Remaining()%13 != 0 {
		return nil, errors.New("PREF64 capsule length is not a multiple of 13")
	}
	var prefixes []netip.Prefix
	for r.Remaining() > 0 {
		prefixLen, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch prefixLen {
		case 32, 40, 48, 56, 64, 96:
		default:
			return nil, fmt.Errorf("invalid NAT64 prefix length: %d", prefixLen)
		}
		var addrBytes [16]byte
		if _, err := io.ReadFull(r, addrBytes[:12]); err != nil {
			return nil, err
		}
		prefix := netip.PrefixFrom(netip.AddrFrom16(addrBytes), int(prefixLen))
		if prefix != prefix.Masked() {
			return nil, errors.New("lower bits not covered by NAT64 prefix length are not all zero")
		}
		prefixes = append(prefixes, prefix)
	}
	return &pref64Capsule{Prefixes: prefixes}, nil
}

func (c *pref64Capsule) append(b []byte) []byte {
	b = quicvarint.Append(b, uint64(capsuleTypePREF64))
	b = quicvarint.Append(b, uint64(13*len(c.Prefixes)))
	for _, prefix := range c.Prefixes {
		b = append(b, byte(prefix.Bits()))
		addr := prefix.Addr().As16()
		b = append(b, addr[:12]...)
	}
	return b
}
