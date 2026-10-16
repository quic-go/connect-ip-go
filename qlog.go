package connectip

import (
	"maps"
	"slices"

	"github.com/quic-go/connect-ip-go/qlog"
	"github.com/quic-go/quic-go/quicvarint"
)

// countingByteReader counts the bytes read from a stream,
// allowing us to log the length of parsed capsules, including the Type and Length fields.
type countingByteReader struct {
	quicvarint.Reader
	NumRead int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	b, err := r.Reader.ReadByte()
	if err == nil {
		r.NumRead++
	}
	return b, err
}

func (r *countingByteReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.NumRead += n
	return n, err
}

func (r *countingByteReader) Reset() {
	r.NumRead = 0
}

// toQlogCapsule converts a capsule into its qlog representation.
// qlog events are encoded asynchronously, so the representation must not share memory with the capsule.
func toQlogCapsule(c capsule, raw qlog.RawInfo) qlog.Capsule {
	switch c := c.(type) {
	case *addressAssignCapsule:
		addrs := make([]qlog.Address, 0, len(c.AssignedAddresses))
		for _, a := range c.AssignedAddresses {
			addrs = append(addrs, qlog.Address{RequestID: uint64(a.RequestID), IPPrefix: a.IPPrefix})
		}
		return qlog.Capsule{Capsule: qlog.AddressAssignCapsule{AssignedAddresses: addrs, Raw: raw}}
	case *addressRequestCapsule:
		addrs := make([]qlog.Address, 0, len(c.Prefixes))
		for i, p := range c.Prefixes {
			addrs = append(addrs, qlog.Address{RequestID: uint64(c.RequestIDs[i]), IPPrefix: p})
		}
		return qlog.Capsule{Capsule: qlog.AddressRequestCapsule{RequestedAddresses: addrs, Raw: raw}}
	case *routeAdvertisementCapsule:
		ranges := make([]qlog.IPAddressRange, 0, len(c.IPAddressRanges))
		for _, r := range c.IPAddressRanges {
			ranges = append(ranges, qlog.IPAddressRange{StartIP: r.StartIP, EndIP: r.EndIP, IPProtocol: r.IPProtocol})
		}
		return qlog.Capsule{Capsule: qlog.RouteAdvertisementCapsule{IPAddressRanges: ranges, Raw: raw}}
	case *dnsAssignCapsule:
		configurations := make([]qlog.DNSConfiguration, 0, len(c.DNSConfigurations))
		for _, cfg := range c.DNSConfigurations {
			configurations = append(configurations, toQlogDNSConfiguration(cfg))
		}
		return qlog.Capsule{Capsule: qlog.DNSAssignCapsule{DNSConfigurations: configurations, Raw: raw}}
	case *pref64Capsule:
		return qlog.Capsule{Capsule: qlog.PREF64Capsule{Prefixes: slices.Clone(c.Prefixes), Raw: raw}}
	}
	// This shouldn't happen, since all capsule types are handled above.
	// The zero value is encoded as null, which is still valid JSON.
	return qlog.Capsule{}
}

func toQlogDNSConfiguration(cfg DNSConfiguration) qlog.DNSConfiguration {
	nameservers := make([]qlog.DNSNameserver, 0, len(cfg.Nameservers))
	for _, ns := range cfg.Nameservers {
		params := make([]qlog.DNSServiceParameter, 0, len(ns.ServiceParameters))
		for _, key := range slices.Sorted(maps.Keys(ns.ServiceParameters)) {
			params = append(params, qlog.DNSServiceParameter{
				Key:   uint16(key),
				Value: slices.Clone(ns.ServiceParameters[key]),
			})
		}
		nameservers = append(nameservers, qlog.DNSNameserver{
			ServicePriority:          ns.ServicePriority,
			IPv4Addresses:            slices.Clone(ns.IPv4Addresses),
			IPv6Addresses:            slices.Clone(ns.IPv6Addresses),
			AuthenticationDomainName: ns.AuthenticationDomainName,
			ServiceParameters:        params,
		})
	}
	return qlog.DNSConfiguration{
		Nameservers:     nameservers,
		InternalDomains: slices.Clone(cfg.InternalDomains),
		SearchDomains:   slices.Clone(cfg.SearchDomains),
	}
}
