package connectip

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpInvokingPacket returns the invoking packet of an ICMP error message, i.e. the packet that caused the error.
// It returns false if b isn't an ICMP error message. b must have been accepted by parseIPHeader.
//
// The invoking packet is truncated if the ICMP error message would otherwise exceed 576 bytes
// for IPv4 (Section 4.3.2.3 of RFC 1812), or the minimum MTU for IPv6 (Section 2.4 of RFC 4443).
// It is empty if the ICMP header itself is truncated.
func icmpInvokingPacket(b []byte, ipProto uint8) (invoking []byte, ok bool) {
	var msg []byte
	switch {
	case ipVersion(b) == 4 && ipProto == ipProtoICMP:
		msg = upperLayerPayload(b)
		if len(msg) == 0 {
			return nil, false
		}
		// Unlike ICMPv6, ICMPv4 doesn't reserve a range of message types for errors.
		// Redirect and Source Quench messages also quote the packet that caused them,
		// but we treat them like any other ICMP message: Redirects only apply to hosts
		// on the same link as the router, and Source Quench is deprecated (see RFC 6633).
		switch ipv4.ICMPType(msg[0]) {
		case ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeParameterProblem:
		default:
			return nil, false
		}
	case ipVersion(b) == 6 && ipProto == ipProtoICMPv6:
		msg = upperLayerPayload(b)
		// ICMPv6 error messages have types from 0 to 127, see Section 2.1 of RFC 4443
		if len(msg) == 0 || msg[0] >= 128 {
			return nil, false
		}
	default:
		return nil, false
	}
	// The invoking packet follows the 8 byte ICMP header.
	// For ICMPv6, this also applies to unknown error message types, see Section 2.4 and Appendix A of RFC 4443.
	if len(msg) < 8 {
		return nil, true
	}
	return msg[8:], true
}

const icmpHopLimit = 64

type icmpPacket struct {
	Src, Dst netip.Addr
	Type     uint8
	Code     uint8
	MTU      uint32
	Data     []byte
}

// b must have been accepted by parseIPHeader.
func newICMPTooLargePacket(b []byte, mtu uint32) *icmpPacket {
	if ipVersion(b) == 4 {
		// RFC 1812, section 4.3.2.3 recommends quoting as much of the original
		// packet as possible without exceeding 576 bytes, including the IPv4 and ICMP headers.
		const maxDataLen = 576 - ipv4.HeaderLen - 8
		return &icmpPacket{
			Src:  netip.AddrFrom4([4]byte(b[16:20])), // the destination of the original packet
			Dst:  netip.AddrFrom4([4]byte(b[12:16])), // the source of the original packet
			Type: uint8(ipv4.ICMPTypeDestinationUnreachable),
			Code: 4, // Fragmentation Needed and Don't Fragment was Set
			MTU:  mtu,
			Data: b[:min(len(b), maxDataLen)],
		}
	}
	return &icmpPacket{
		Src:  netip.AddrFrom16([16]byte(b[24:40])), // the destination of the original packet
		Dst:  netip.AddrFrom16([16]byte(b[8:24])),  // the source of the original packet
		Type: uint8(ipv6.ICMPTypePacketTooBig),
		MTU:  mtu,
		Data: b[:min(len(b), 1232)],
	}
}

func (p *icmpPacket) Marshal() ([]byte, error) {
	msg := &icmp.Message{
		Code: int(p.Code),
		Body: &icmp.PacketTooBig{MTU: int(p.MTU), Data: p.Data},
	}
	if p.Src.Is4() {
		msg.Type = ipv4.ICMPType(p.Type)
		b, err := msg.Marshal(nil)
		if err != nil {
			return nil, fmt.Errorf("connect-ip: failed to marshal ICMP message: %w", err)
		}
		src, dst := p.Src.As4(), p.Dst.As4()
		var header [ipv4.HeaderLen]byte
		header[0] = 4<<4 | ipv4.HeaderLen>>2                                   // Version and IHL
		binary.BigEndian.PutUint16(header[2:4], uint16(ipv4.HeaderLen+len(b))) // Total Length
		header[8] = icmpHopLimit                                               // TTL
		header[9] = ipProtoICMP                                                // Protocol
		copy(header[12:16], src[:])
		copy(header[16:20], dst[:])
		binary.BigEndian.PutUint16(header[10:12], calculateIPv4Checksum(header[:]))
		return append(header[:], b...), nil
	}

	src, dst := p.Src.As16(), p.Dst.As16()
	msg.Type = ipv6.ICMPType(p.Type)
	b, err := msg.Marshal(icmp.IPv6PseudoHeader(src[:], dst[:]))
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to marshal ICMP message: %w", err)
	}
	var header [ipv6.HeaderLen]byte
	header[0] = 6 << 4                                      // Version
	binary.BigEndian.PutUint16(header[4:6], uint16(len(b))) // Payload Length
	header[6] = ipProtoICMPv6                               // Next Header
	header[7] = icmpHopLimit                                // Hop Limit
	copy(header[8:24], src[:])
	copy(header[24:40], dst[:])
	return append(header[:], b...), nil
}
