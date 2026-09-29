package connectip

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

// parseIPHeader returns the source and destination addresses and the upper-layer protocol of an IP packet.
func parseIPHeader(b []byte) (src, dst netip.Addr, ipProto uint8, err error) {
	if len(b) == 0 {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: empty packet")
	}
	switch v := ipVersion(b); v {
	default:
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: IPv4 packet too short")
		}
		if err := validateIPv4Checksum(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
		if err := validateIPv4TotalLength(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		ipProto = b[9]
	case 6:
		if len(b) < ipv6.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: IPv6 packet too short")
		}
		if err := validateIPv6PayloadLength(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		if ipProto, err = ipv6UpperLayerProtocol(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
	}
	return src, dst, ipProto, nil
}

// isAllowedDestination checks if dst is within one of the prefixes,
// or within one of the routes that allow the IP protocol.
func isAllowedDestination(dst netip.Addr, ipProto uint8, prefixes []netip.Prefix, routes []IPRoute) bool {
	for _, p := range prefixes {
		if p.Contains(dst) {
			return true
		}
	}
	// ICMP is always allowed
	isICMP := (dst.Is4() && ipProto == ipProtoICMP) || (dst.Is6() && ipProto == ipProtoICMPv6)
	// Fragments at non-zero fragment offsets don't contain the upper-layer header.
	// For a stateless firewall, there's no way to reassemble the original packet.
	// In that case, we'd only drop the first fragment, but forward the rest.
	// Without the first fragment, the receiver will not be able to reassemble the original packet.
	// See Section 4 of RFC 7112.
	isFragment := dst.Is6() && ipProto == ipProtoFragment
	for _, r := range routes {
		if !r.contains(dst) {
			continue
		}
		if isICMP || isFragment || r.IPProtocol == 0 || r.IPProtocol == ipProto {
			return true
		}
	}
	return false
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }
