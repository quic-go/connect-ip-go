package qlog

import (
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

const (
	// EventSchemaHTTP is the qlog event schema for the HTTP Capsule Protocol,
	// defined in draft-ietf-quic-qlog-h3-events-13.
	// It defines the http:capsule_created and http:capsule_parsed events.
	EventSchemaHTTP = "urn:ietf:params:qlog:events:http-13"
	// EventSchemaConnectIP is the qlog event schema for CONNECT-IP,
	// defined in draft-seemann-masque-connect-ip-qlog-00.
	EventSchemaConnectIP = "urn:ietf:params:qlog:events:http#connect-ip-00"
	// EventSchemaConnectIPDNS is the qlog event schema for the DNS_ASSIGN and PREF64 capsules,
	// defined in draft-seemann-masque-connect-ip-qlog-00.
	EventSchemaConnectIPDNS = "urn:ietf:params:qlog:events:http#connect-ip-dns-00"
)

func init() {
	qlogwriter.RegisterEventSchema(EventSchemaHTTP)
	qlogwriter.RegisterEventSchema(EventSchemaConnectIP)
	qlogwriter.RegisterEventSchema(EventSchemaConnectIPDNS)
}

type encoderHelper struct {
	enc *jsontext.Encoder
	err error
}

func (h *encoderHelper) WriteToken(t jsontext.Token) {
	if h.err != nil {
		return
	}
	h.err = h.enc.WriteToken(t)
}

// OmitLength indicates that a length should not be logged.
const OmitLength = -1

// RawInfo contains capsule or packet lengths. Zero lengths are logged.
// Set a field to OmitLength to omit it.
type RawInfo struct {
	Length        int // full length of the capsule or packet
	PayloadLength int // length of the capsule value or packet payload
}

func (i RawInfo) HasValues() bool {
	return i.Length != OmitLength || i.PayloadLength != OmitLength
}

func (i RawInfo) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if i.Length != OmitLength {
		h.WriteToken(jsontext.String("length"))
		h.WriteToken(jsontext.Uint(uint64(i.Length)))
	}
	if i.PayloadLength != OmitLength {
		h.WriteToken(jsontext.String("payload_length"))
		h.WriteToken(jsontext.Uint(uint64(i.PayloadLength)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type CapsuleCreated struct {
	StreamID quic.StreamID
	Capsule  Capsule
}

func (e CapsuleCreated) Name() string { return "http:capsule_created" }

func (e CapsuleCreated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(e.StreamID)))
	h.WriteToken(jsontext.String("capsule"))
	if err := e.Capsule.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type CapsuleParsed struct {
	StreamID quic.StreamID
	Capsule  Capsule
}

func (e CapsuleParsed) Name() string { return "http:capsule_parsed" }

func (e CapsuleParsed) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(e.StreamID)))
	h.WriteToken(jsontext.String("capsule"))
	if err := e.Capsule.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketProcessed struct {
	StreamID     quic.StreamID
	Source       Endpoint
	Packet       Packet
	Outcome      PacketOutcome
	Reason       PacketDropReason
	ICMPResponse *ICMPResponse
}

func (e PacketProcessed) Name() string { return "http:connect_ip_packet_processed" }

func (e PacketProcessed) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("stream_id"))
	h.WriteToken(jsontext.Uint(uint64(e.StreamID)))
	h.WriteToken(jsontext.String("source"))
	h.WriteToken(jsontext.String(string(e.Source)))
	h.WriteToken(jsontext.String("packet"))
	if err := e.Packet.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("outcome"))
	h.WriteToken(jsontext.String(string(e.Outcome)))
	if e.Reason != "" {
		h.WriteToken(jsontext.String("reason"))
		h.WriteToken(jsontext.String(string(e.Reason)))
	}
	if e.ICMPResponse != nil {
		h.WriteToken(jsontext.String("icmp_response"))
		if err := e.ICMPResponse.encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}
