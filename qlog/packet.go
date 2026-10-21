package qlog

import (
	"net/netip"

	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

// Endpoint is the local application or the peer.
type Endpoint string

const (
	EndpointApplication Endpoint = "application"
	EndpointPeer        Endpoint = "peer"
)

// PacketOutcome is the forwarding decision for a packet.
type PacketOutcome string

const (
	PacketForwarded PacketOutcome = "forwarded"
	PacketDropped   PacketOutcome = "dropped"
)

// PacketDropReason is the reason why a packet was dropped.
type PacketDropReason string

const (
	PacketDropInvalid                      PacketDropReason = "invalid"
	PacketDropSourceAddressNotAllowed      PacketDropReason = "source_address_not_allowed"
	PacketDropDestinationAddressNotAllowed PacketDropReason = "destination_address_not_allowed"
	PacketDropProtocolNotAllowed           PacketDropReason = "protocol_not_allowed"
	PacketDropHopLimitExceeded             PacketDropReason = "hop_limit_exceeded"
	PacketDropTooLarge                     PacketDropReason = "packet_too_large"
	PacketDropSendError                    PacketDropReason = "send_error"
	PacketDropOther                        PacketDropReason = "other"
)

// An IPHeader is an IPv4Header or an IPv6Header.
type IPHeader interface {
	encode(*jsontext.Encoder) error
}

// A Packet is an IP packet.
type Packet struct {
	Header             IPHeader
	UpperLayerProtocol *uint8
	ICMP               *ICMP
	Raw                RawInfo
}

func (p Packet) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if p.Header != nil {
		h.WriteToken(jsontext.String("header"))
		if err := p.Header.encode(enc); err != nil {
			return err
		}
	}
	if p.UpperLayerProtocol != nil {
		h.WriteToken(jsontext.String("upper_layer_protocol"))
		h.WriteToken(jsontext.Uint(uint64(*p.UpperLayerProtocol)))
	}
	if p.ICMP != nil {
		h.WriteToken(jsontext.String("icmp"))
		if err := p.ICMP.encode(enc); err != nil {
			return err
		}
	}
	if p.Raw.HasValues() {
		h.WriteToken(jsontext.String("raw"))
		if err := p.Raw.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An IPv4Header is the header of an IPv4 packet.
type IPv4Header struct {
	TotalLength        uint16
	TTL                uint8
	Protocol           uint8
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
}

func (hdr IPv4Header) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("version"))
	h.WriteToken(jsontext.Uint(4))
	h.WriteToken(jsontext.String("total_length"))
	h.WriteToken(jsontext.Uint(uint64(hdr.TotalLength)))
	h.WriteToken(jsontext.String("ttl"))
	h.WriteToken(jsontext.Uint(uint64(hdr.TTL)))
	h.WriteToken(jsontext.String("protocol"))
	h.WriteToken(jsontext.Uint(uint64(hdr.Protocol)))
	h.WriteToken(jsontext.String("source_address"))
	h.WriteToken(jsontext.String(hdr.SourceAddress.String()))
	h.WriteToken(jsontext.String("destination_address"))
	h.WriteToken(jsontext.String(hdr.DestinationAddress.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An IPv6Header is the fixed header of an IPv6 packet.
type IPv6Header struct {
	PayloadLength      uint16
	NextHeader         uint8
	HopLimit           uint8
	SourceAddress      netip.Addr
	DestinationAddress netip.Addr
}

func (hdr IPv6Header) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("version"))
	h.WriteToken(jsontext.Uint(6))
	h.WriteToken(jsontext.String("payload_length"))
	h.WriteToken(jsontext.Uint(uint64(hdr.PayloadLength)))
	h.WriteToken(jsontext.String("next_header"))
	h.WriteToken(jsontext.Uint(uint64(hdr.NextHeader)))
	h.WriteToken(jsontext.String("hop_limit"))
	h.WriteToken(jsontext.Uint(uint64(hdr.HopLimit)))
	h.WriteToken(jsontext.String("source_address"))
	h.WriteToken(jsontext.String(hdr.SourceAddress.String()))
	h.WriteToken(jsontext.String("destination_address"))
	h.WriteToken(jsontext.String(hdr.DestinationAddress.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// ICMP is the ICMP or ICMPv6 message carried in a packet.
type ICMP struct {
	Type uint8
	Code uint8
	MTU  uint32
}

func (i ICMP) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("type"))
	h.WriteToken(jsontext.Uint(uint64(i.Type)))
	h.WriteToken(jsontext.String("code"))
	h.WriteToken(jsontext.Uint(uint64(i.Code)))
	if i.MTU != 0 {
		h.WriteToken(jsontext.String("mtu"))
		h.WriteToken(jsontext.Uint(uint64(i.MTU)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// An ICMPResponse is an ICMP message generated in response to a packet.
type ICMPResponse struct {
	To     Endpoint
	Packet Packet
}

func (r ICMPResponse) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("to"))
	h.WriteToken(jsontext.String(string(r.To)))
	h.WriteToken(jsontext.String("packet"))
	if err := r.Packet.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
