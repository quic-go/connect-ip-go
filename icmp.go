package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"

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
		// fragments at non-zero fragment offsets don't contain the ICMP header
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return nil, false
		}
		msg = b[int(b[0]&0x0f)*4:]
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
		_, msg, _ = ipv6UpperLayerProtocol(b)
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

func composeICMPTooLargePacket(b []byte, mtu int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("connect-ip: empty packet")
	}

	var icmpMessage *icmp.Message
	var psh []byte
	switch v := ipVersion(b); v {
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, errors.New("connect-ip: IPv4 packet too short")
		}
		// RFC 1812, section 4.3.2.3 recommends quoting as much of the original
		// packet as possible without exceeding 576 bytes, including the IPv4 and ICMP headers.
		const maxDataLen = 576 - ipv4.HeaderLen - 8
		icmpMessage = &icmp.Message{
			Type: ipv4.ICMPTypeDestinationUnreachable,
			Code: 4, // Fragmentation Needed and Don't Fragment was Set
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: b[:min(len(b), maxDataLen)],
			},
		}
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, errors.New("connect-ip: IPv6 packet too short")
		}
		icmpMessage = &icmp.Message{
			Type: ipv6.ICMPTypePacketTooBig,
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: b[:min(len(b), 1232)],
			},
		}
		psh = icmp.IPv6PseudoHeader(b[24:40], b[8:24])
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP version: %d", v)
	}

	icmp, err := icmpMessage.Marshal(psh)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to marshal ICMP message: %w", err)
	}

	if ipVersion(b) == 4 {
		var header [ipv4.HeaderLen]byte
		header[0] = 4<<4 | ipv4.HeaderLen>>2 // Version and IHL
		ipLen := ipv4.HeaderLen + len(icmp)
		binary.BigEndian.PutUint16(header[2:4], uint16(ipLen)) // Total Length
		header[8] = 64                                         // TTL
		header[9] = 1                                          // Protocol (ICMP)
		copy(header[12:16], b[16:20])                          // Source IP from original packet
		copy(header[16:20], b[12:16])                          // Dest IP from original packet (swapped)
		binary.BigEndian.PutUint16(header[10:12], calculateIPv4Checksum(header[:]))
		return append(header[:], icmp...), nil
	}

	var header [ipv6.HeaderLen]byte
	header[0] = 6 << 4                                         // Version 6
	binary.BigEndian.PutUint16(header[4:6], uint16(len(icmp))) // Payload Length
	header[6] = 58                                             // Next Header (ICMPv6)
	header[7] = 64                                             // Hop Limit
	copy(header[8:24], b[24:40])                               // Source IP from original packet
	copy(header[24:40], b[8:24])                               // Dest IP from original packet (swapped)
	return append(header[:], icmp...), nil
}
