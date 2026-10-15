package qlog

import (
	"encoding/hex"
	"net/netip"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// Capsule represents a capsule sent or received on the CONNECT-IP request stream.
type Capsule struct {
	Capsule any
}

func (c Capsule) encode(enc *jsontext.Encoder) error {
	switch capsule := c.Capsule.(type) {
	case AddressAssignCapsule:
		return capsule.encode(enc)
	case AddressRequestCapsule:
		return capsule.encode(enc)
	case RouteAdvertisementCapsule:
		return capsule.encode(enc)
	case DNSAssignCapsule:
		return capsule.encode(enc)
	case PREF64Capsule:
		return capsule.encode(enc)
	case UnknownCapsule:
		return capsule.encode(enc)
	}
	// This shouldn't happen if the code is correctly logging capsules.
	// Write a null token to produce valid JSON.
	return enc.WriteToken(jsontext.Null)
}

// An Address is an address contained in an ADDRESS_ASSIGN or an ADDRESS_REQUEST capsule.
type Address struct {
	RequestID uint64
	IPPrefix  netip.Prefix
}

func (a Address) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("request_id"))
	h.WriteToken(jsontext.Uint(a.RequestID))
	h.WriteToken(jsontext.String("ip_prefix"))
	h.WriteToken(jsontext.String(a.IPPrefix.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An AddressAssignCapsule is an ADDRESS_ASSIGN capsule.
type AddressAssignCapsule struct {
	AssignedAddresses []Address
	Raw               RawInfo
}

func (c *AddressAssignCapsule) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("capsule_type"))
	h.WriteToken(jsontext.String("address_assign"))
	h.WriteToken(jsontext.String("assigned_addresses"))
	h.WriteToken(jsontext.BeginArray)
	for _, a := range c.AssignedAddresses {
		if err := a.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	if c.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := c.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An AddressRequestCapsule is an ADDRESS_REQUEST capsule.
type AddressRequestCapsule struct {
	RequestedAddresses []Address
	Raw                RawInfo
}

func (c *AddressRequestCapsule) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("capsule_type"))
	h.WriteToken(jsontext.String("address_request"))
	h.WriteToken(jsontext.String("requested_addresses"))
	h.WriteToken(jsontext.BeginArray)
	for _, a := range c.RequestedAddresses {
		if err := a.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	if c.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := c.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An IPAddressRange is an IP address range contained in a ROUTE_ADVERTISEMENT capsule.
type IPAddressRange struct {
	StartIP    netip.Addr
	EndIP      netip.Addr
	IPProtocol uint8
}

func (r IPAddressRange) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("start_ip"))
	h.WriteToken(jsontext.String(r.StartIP.String()))
	h.WriteToken(jsontext.String("end_ip"))
	h.WriteToken(jsontext.String(r.EndIP.String()))
	h.WriteToken(jsontext.String("ip_protocol"))
	h.WriteToken(jsontext.Uint(uint64(r.IPProtocol)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A RouteAdvertisementCapsule is a ROUTE_ADVERTISEMENT capsule.
type RouteAdvertisementCapsule struct {
	IPAddressRanges []IPAddressRange
	Raw             RawInfo
}

func (c *RouteAdvertisementCapsule) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("capsule_type"))
	h.WriteToken(jsontext.String("route_advertisement"))
	h.WriteToken(jsontext.String("ip_address_ranges"))
	h.WriteToken(jsontext.BeginArray)
	for _, r := range c.IPAddressRanges {
		if err := r.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	if c.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := c.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A DNSServiceParameter is an SVCB service parameter of a DNS nameserver.
type DNSServiceParameter struct {
	Key   uint16
	Value []byte // the wire-format SvcParamValue
}

func (p DNSServiceParameter) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("key"))
	h.WriteToken(jsontext.Uint(uint64(p.Key)))
	h.WriteToken(jsontext.String("value"))
	h.WriteToken(jsontext.String(hex.EncodeToString(p.Value)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A DNSNameserver is a nameserver contained in a DNS configuration.
type DNSNameserver struct {
	ServicePriority          uint16
	IPv4Addresses            []netip.Addr
	IPv6Addresses            []netip.Addr
	AuthenticationDomainName string
	// ServiceParameters are sorted by key.
	ServiceParameters []DNSServiceParameter
}

func (n DNSNameserver) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("service_priority"))
	h.WriteToken(jsontext.Uint(uint64(n.ServicePriority)))
	h.WriteToken(jsontext.String("ipv4_addresses"))
	h.WriteToken(jsontext.BeginArray)
	for _, addr := range n.IPv4Addresses {
		h.WriteToken(jsontext.String(addr.String()))
	}
	h.WriteToken(jsontext.EndArray)
	h.WriteToken(jsontext.String("ipv6_addresses"))
	h.WriteToken(jsontext.BeginArray)
	for _, addr := range n.IPv6Addresses {
		h.WriteToken(jsontext.String(addr.String()))
	}
	h.WriteToken(jsontext.EndArray)
	h.WriteToken(jsontext.String("authentication_domain_name"))
	h.WriteToken(jsontext.String(n.AuthenticationDomainName))
	h.WriteToken(jsontext.String("service_parameters"))
	h.WriteToken(jsontext.BeginArray)
	for _, p := range n.ServiceParameters {
		if err := p.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A DNSConfiguration is a DNS configuration contained in a DNS_ASSIGN capsule.
type DNSConfiguration struct {
	Nameservers     []DNSNameserver
	InternalDomains []string
	SearchDomains   []string
}

func (c DNSConfiguration) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("nameservers"))
	h.WriteToken(jsontext.BeginArray)
	for _, ns := range c.Nameservers {
		if err := ns.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	h.WriteToken(jsontext.String("internal_domains"))
	h.WriteToken(jsontext.BeginArray)
	for _, domain := range c.InternalDomains {
		h.WriteToken(jsontext.String(domain))
	}
	h.WriteToken(jsontext.EndArray)
	h.WriteToken(jsontext.String("search_domains"))
	h.WriteToken(jsontext.BeginArray)
	for _, domain := range c.SearchDomains {
		h.WriteToken(jsontext.String(domain))
	}
	h.WriteToken(jsontext.EndArray)
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A DNSAssignCapsule is a DNS_ASSIGN capsule.
type DNSAssignCapsule struct {
	DNSConfigurations []DNSConfiguration
	Raw               RawInfo
}

func (c *DNSAssignCapsule) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("capsule_type"))
	h.WriteToken(jsontext.String("dns_assign"))
	h.WriteToken(jsontext.String("dns_configurations"))
	h.WriteToken(jsontext.BeginArray)
	for _, cfg := range c.DNSConfigurations {
		if err := cfg.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndArray)
	if c.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := c.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// A PREF64Capsule is a PREF64 capsule.
type PREF64Capsule struct {
	Prefixes []netip.Prefix
	Raw      RawInfo
}

func (c *PREF64Capsule) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("capsule_type"))
	h.WriteToken(jsontext.String("pref64"))
	h.WriteToken(jsontext.String("prefixes"))
	h.WriteToken(jsontext.BeginArray)
	for _, prefix := range c.Prefixes {
		h.WriteToken(jsontext.String(prefix.String()))
	}
	h.WriteToken(jsontext.EndArray)
	if c.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := c.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An UnknownCapsule is a capsule of a type that connect-ip-go doesn't process.
type UnknownCapsule struct {
	Type uint64
	Raw  RawInfo
}

func (c *UnknownCapsule) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("capsule_type"))
	h.WriteToken(jsontext.String("unknown"))
	h.WriteToken(jsontext.String("capsule_type_value"))
	h.WriteToken(jsontext.Uint(c.Type))
	if c.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := c.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
