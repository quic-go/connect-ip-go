package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"slices"

	"golang.org/x/net/dns/dnsmessage"

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

// Bound the memory used to parse and retain a peer's addresses and routes.
const (
	maxAddressesPerCapsule = 8192
	maxRoutesPerCapsule    = 8192
)

// addressAssignCapsule represents an ADDRESS_ASSIGN capsule
type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

// AssignedAddress represents an Assigned Address within an ADDRESS_ASSIGN capsule
type AssignedAddress struct {
	// RequestID is zero for an unsolicited assignment.
	RequestID AddressRequestID
	IPPrefix  netip.Prefix
}

// Rejected reports whether the assignment is a refusal (0.0.0.0/32 or ::/128).
func (a AssignedAddress) Rejected() bool {
	return a.IPPrefix == rejectedIPv4Prefix || a.IPPrefix == rejectedIPv6Prefix
}

func (a AssignedAddress) len() int {
	return quicvarint.Len(uint64(a.RequestID)) + 1 + a.IPPrefix.Addr().BitLen()/8 + 1
}

// addressRequestCapsule represents an ADDRESS_REQUEST capsule
type addressRequestCapsule struct {
	// RequestIDs and Prefixes have matching lengths and order.
	RequestIDs []AddressRequestID
	Prefixes   []netip.Prefix
}

func parseAddressAssignCapsule(r http3.CapsuleReader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for r.Remaining() > 0 {
		if len(assignedAddresses) >= maxAddressesPerCapsule {
			return nil, fmt.Errorf("ADDRESS_ASSIGN capsule contains too many addresses (maximum %d)", maxAddressesPerCapsule)
		}
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, AssignedAddress{RequestID: AddressRequestID(requestID), IPPrefix: prefix})
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
		b = quicvarint.Append(b, uint64(addr.RequestID))
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

func parseAddressRequestCapsule(r http3.CapsuleReader) (*addressRequestCapsule, error) {
	if r.Remaining() == 0 {
		return nil, errors.New("ADDRESS_REQUEST capsule contains no addresses")
	}
	capsule := &addressRequestCapsule{}
	for r.Remaining() > 0 {
		if len(capsule.Prefixes) >= maxAddressesPerCapsule {
			return nil, fmt.Errorf("ADDRESS_REQUEST capsule contains too many addresses (maximum %d)", maxAddressesPerCapsule)
		}
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			return nil, err
		}
		if requestID == 0 {
			return nil, errors.New("ADDRESS_REQUEST capsule contains a zero request ID")
		}
		capsule.RequestIDs = append(capsule.RequestIDs, AddressRequestID(requestID))
		capsule.Prefixes = append(capsule.Prefixes, prefix)
	}
	return capsule, nil
}

func (c *addressRequestCapsule) append(b []byte) []byte {
	var totalLen int
	for i, p := range c.Prefixes {
		totalLen += quicvarint.Len(uint64(c.RequestIDs[i])) + 1 + p.Addr().BitLen()/8 + 1
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressRequest))
	b = quicvarint.Append(b, uint64(totalLen))

	for i, p := range c.Prefixes {
		b = quicvarint.Append(b, uint64(c.RequestIDs[i]))
		if p.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, p.Addr().AsSlice()...)
		b = append(b, byte(p.Bits()))
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

// validateRouteAdvertisement checks the endpoints, ordering, and overlap rules in RFC 9484, Section 4.7.3.
// https://www.rfc-editor.org/rfc/rfc9484.html#section-4.7.3
func validateRouteAdvertisement(routes []IPRoute) error {
	var numIPv4, numIPv4Protocol0, numIPv6Protocol0 int
	for _, route := range routes {
		if !route.StartIP.IsValid() || !route.EndIP.IsValid() {
			return errors.New("invalid route: IP addresses must be valid")
		}
		if route.StartIP.Is4() != route.EndIP.Is4() {
			return errors.New("invalid route: IP addresses must have the same address family")
		}
		if route.StartIP.Zone() != "" || route.EndIP.Zone() != "" {
			return errors.New("invalid route: IP addresses must not have zones")
		}
		if route.StartIP.Compare(route.EndIP) > 0 {
			return fmt.Errorf("invalid route: start IP %s is greater than end IP %s", route.StartIP, route.EndIP)
		}
		if route.StartIP.Is4() {
			numIPv4++
			if route.IPProtocol == 0 {
				numIPv4Protocol0++
			}
		} else if route.IPProtocol == 0 {
			numIPv6Protocol0++
		}
	}

	// The RFC defines three rules for A preceding B. Checking adjacent pairs suffices.
	for i := 1; i < len(routes); i++ {
		a := routes[i-1]
		b := routes[i]
		// 1. "The IP Version of A MUST be less than or equal to the IP Version of B."
		if a.StartIP.BitLen() > b.StartIP.BitLen() {
			return errors.New("route IP versions must be in increasing order")
		}
		if a.StartIP.BitLen() != b.StartIP.BitLen() {
			continue
		}
		// 2. Within one IP version, protocol(A) <= protocol(B).
		if a.IPProtocol > b.IPProtocol {
			return errors.New("route IP protocols must be in increasing order")
		}
		// 3. With matching versions and protocols, end(A) < start(B).
		if a.IPProtocol == b.IPProtocol && a.EndIP.Compare(b.StartIP) >= 0 {
			return errors.New("route address ranges must be disjoint and in increasing order")
		}
	}

	// Rule 3 only compares routes with equal IPProtocol values.
	// For example, advertising 192.0.2.0-192.0.2.255 with both IPProtocol 0 and 6 passes that check.
	// The RFC forbids this overlap too: IPProtocol == 0 allows all protocols, including 6.
	// Rule 1 groups routes by address family; rule 2 puts protocol 0 first in each family.
	ipv4 := routes[:numIPv4]
	if err := validateNonOverlappingRoutes(ipv4[:numIPv4Protocol0], ipv4[numIPv4Protocol0:]); err != nil {
		return err
	}
	ipv6 := routes[numIPv4:]
	return validateNonOverlappingRoutes(ipv6[:numIPv6Protocol0], ipv6[numIPv6Protocol0:])
}

// validateNonOverlappingRoutes checks routes allowing all protocols against routes
// allowing a specific protocol. Both slices must belong to the same address family
// and already be sorted by protocol and address.
func validateNonOverlappingRoutes(all, specific []IPRoute) error {
	var j int // cursor into all
	for i, b := range specific {
		if i > 0 && specific[i-1].IPProtocol != b.IPProtocol {
			j = 0 // address ordering restarts for each protocol
		}
		for j < len(all) {
			a := all[j]
			if a.EndIP.Compare(b.StartIP) < 0 {
				// a ends before b. Skip a for the rest of this protocol
				j++
				continue
			}
			if b.EndIP.Compare(a.StartIP) < 0 {
				// b ends before a and every later route allowing all protocols
				break
			}
			// neither range ends before the other starts: they overlap
			return errors.New("route overlaps a route for all IP protocols")
		}
	}
	return nil
}

func parseRouteAdvertisementCapsule(r http3.CapsuleReader) (*routeAdvertisementCapsule, error) {
	var ranges []IPRoute
	for r.Remaining() > 0 {
		if len(ranges) >= maxRoutesPerCapsule {
			return nil, fmt.Errorf("ROUTE_ADVERTISEMENT capsule contains too many routes (maximum %d)", maxRoutesPerCapsule)
		}
		ipRange, err := parseIPAddressRange(r)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, ipRange)
	}
	if err := validateRouteAdvertisement(ranges); err != nil {
		return nil, err
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

// This limits the wire size, not memory use. Parsing can amplify memory use by
// roughly 50x, and the limit is chosen accordingly.
const maxDNSAssignCapsuleSize = 32 << 10

func parseCounted[T any](r http3.CapsuleReader, parse func(http3.CapsuleReader) (T, error)) ([]T, error) {
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
	if r.Remaining() > maxDNSAssignCapsuleSize {
		return nil, fmt.Errorf("DNS_ASSIGN capsule too large: %d bytes (maximum %d)", r.Remaining(), maxDNSAssignCapsuleSize)
	}
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

func parseDNSNameserver(r http3.CapsuleReader) (DNSNameserver, error) {
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
	if paramsLen > uint64(r.Remaining()) {
		return DNSNameserver{}, io.ErrUnexpectedEOF
	}
	var serviceParameters map[dnsmessage.SVCParamKey][]byte
	if paramsLen > 0 {
		b := make([]byte, int(paramsLen))
		if _, err := io.ReadFull(r, b); err != nil {
			return DNSNameserver{}, err
		}
		serviceParameters = make(map[dnsmessage.SVCParamKey][]byte)
		var previousKey dnsmessage.SVCParamKey
		for len(b) > 0 {
			if len(b) < 4 {
				return DNSNameserver{}, fmt.Errorf("invalid service parameter header: %w", io.ErrUnexpectedEOF)
			}
			key := dnsmessage.SVCParamKey(binary.BigEndian.Uint16(b))
			valueLen := int(binary.BigEndian.Uint16(b[2:]))
			b = b[4:]
			if valueLen > len(b) {
				return DNSNameserver{}, fmt.Errorf("invalid service parameter value: %w", io.ErrUnexpectedEOF)
			}
			if len(serviceParameters) > 0 && key <= previousKey {
				return DNSNameserver{}, errors.New("service parameter keys must be in strictly increasing order")
			}
			// The second index sets capacity so append on the value can't overwrite later parameters.
			serviceParameters[key] = b[:valueLen:valueLen]
			previousKey = key
			b = b[valueLen:]
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

func parseDomain(r http3.CapsuleReader) (string, error) {
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
		for _, ns := range cfg.Nameservers {
			payload = binary.BigEndian.AppendUint16(payload, ns.ServicePriority)
			payload = quicvarint.Append(payload, uint64(len(ns.IPv4Addresses)))
			for _, addr := range ns.IPv4Addresses {
				payload = append(payload, addr.AsSlice()...)
			}
			payload = quicvarint.Append(payload, uint64(len(ns.IPv6Addresses)))
			for _, addr := range ns.IPv6Addresses {
				payload = append(payload, addr.AsSlice()...)
			}
			payload = appendDomain(payload, ns.AuthenticationDomainName)
			keys := slices.Sorted(maps.Keys(ns.ServiceParameters))
			var l int
			for _, key := range keys {
				l += 4 + len(ns.ServiceParameters[key])
			}
			payload = quicvarint.Append(payload, uint64(l))
			for _, key := range keys {
				value := ns.ServiceParameters[key]
				payload = binary.BigEndian.AppendUint16(payload, uint16(key))
				payload = binary.BigEndian.AppendUint16(payload, uint16(len(value)))
				payload = append(payload, value...)
			}
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

const maxPREF64Prefixes = 256

func parsePREF64Capsule(r http3.CapsuleReader) (*pref64Capsule, error) {
	// each prefix consists of a 1-byte prefix length and 12 bytes of address
	if r.Remaining()%13 != 0 {
		return nil, errors.New("PREF64 capsule length is not a multiple of 13")
	}
	numPrefixes := r.Remaining() / 13
	if numPrefixes > maxPREF64Prefixes {
		return nil, fmt.Errorf("PREF64 capsule contains too many prefixes: %d (maximum %d)", numPrefixes, maxPREF64Prefixes)
	}
	prefixes := make([]netip.Prefix, 0, numPrefixes)
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
		if prefix.Addr().Is4In6() {
			return nil, errors.New("IPv4-mapped IPv6 addresses are not valid NAT64 prefixes")
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
