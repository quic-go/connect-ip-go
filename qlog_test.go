package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/connect-ip-go/qlog"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/quic-go/quic-go/testutils/events"

	"golang.org/x/net/ipv4"

	"github.com/stretchr/testify/require"
)

func TestQlogCapsules(t *testing.T) {
	var clientEvents, serverEvents events.Recorder
	client, server := setupConnsWithTracers(t,
		func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: &clientEvents}
		},
		func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &events.Trace{Recorder: &serverEvents}
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	_, err := client.RequestAddresses([]netip.Prefix{prefix})
	require.NoError(t, err)
	req, err := server.ReceiveAddressRequest(ctx)
	require.NoError(t, err)
	require.NoError(t, req.Respond([]netip.Prefix{prefix}, nil))
	_, err = client.ReceiveAddressAssignment(ctx)
	require.NoError(t, err)

	// Both capsules are sent on stream 0 and have a 7-byte value.
	addrs := []qlog.Address{{RequestID: 1, IPPrefix: prefix}}
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CapsuleCreated{
				Capsule: qlog.Capsule{
					Capsule: qlog.AddressRequestCapsule{
						RequestedAddresses: addrs,
						Raw:                qlog.RawInfo{Length: 9, PayloadLength: 7},
					},
				},
			},
		},
		clientEvents.Events(qlog.CapsuleCreated{}),
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CapsuleParsed{
				Capsule: qlog.Capsule{
					Capsule: qlog.AddressRequestCapsule{
						RequestedAddresses: addrs,
						Raw:                qlog.RawInfo{Length: 9, PayloadLength: 7},
					},
				},
			},
		},
		serverEvents.Events(qlog.CapsuleParsed{}),
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CapsuleCreated{
				Capsule: qlog.Capsule{
					Capsule: qlog.AddressAssignCapsule{
						AssignedAddresses: addrs,
						Raw:               qlog.RawInfo{Length: 9, PayloadLength: 7},
					},
				},
			},
		},
		serverEvents.Events(qlog.CapsuleCreated{}),
	)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CapsuleParsed{
				Capsule: qlog.Capsule{
					Capsule: qlog.AddressAssignCapsule{
						AssignedAddresses: addrs,
						Raw:               qlog.RawInfo{Length: 9, PayloadLength: 7},
					},
				},
			},
		},
		clientEvents.Events(qlog.CapsuleParsed{}),
	)
}

type closeTrackingRecorder struct {
	events.Recorder
	closed chan struct{}
}

func (r *closeTrackingRecorder) Close() error {
	close(r.closed)
	return nil
}

func TestQlogUnknownCapsule(t *testing.T) {
	recorder := &closeTrackingRecorder{closed: make(chan struct{})}
	readChan := make(chan []byte, 1)
	newProxiedConn(&mockStream{toRead: readChan, qlogTrace: &events.Trace{Recorder: recorder}}, nil)

	data := quicvarint.Append(nil, 42)
	data = quicvarint.AppendWithLen(data, 3, 8) // non-minimal encoding of the Length field
	data = append(data, "foo"...)
	data = (&pref64Capsule{Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}}).append(data)
	readChan <- data
	close(readChan) // the peer closes the stream, which closes the recorder

	select {
	case <-recorder.closed:
	case <-time.After(time.Second):
		t.Fatal("recorder wasn't closed")
	}
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.CapsuleParsed{Capsule: qlog.Capsule{Capsule: qlog.UnknownCapsule{
				Type: 42,
				Raw:  qlog.RawInfo{Length: 12, PayloadLength: 3},
			}}},
			qlog.CapsuleParsed{Capsule: qlog.Capsule{Capsule: qlog.PREF64Capsule{
				Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
				Raw:      qlog.RawInfo{Length: 18, PayloadLength: 13},
			}}},
		},
		recorder.Events(),
	)
}

func qlogIPv4Packet(ttl, protocol uint8, src, dst string) qlog.Packet {
	return qlog.Packet{
		Header: qlog.IPv4Header{
			TotalLength:        20,
			TTL:                ttl,
			Protocol:           protocol,
			SourceAddress:      netip.MustParseAddr(src),
			DestinationAddress: netip.MustParseAddr(dst),
		},
		Raw: qlog.RawInfo{Length: 20},
	}
}

func TestQlogReadPacket(t *testing.T) {
	var recorder events.Recorder
	datagrams := make(chan []byte, 4)
	conn := newProxiedConn(&mockStream{datagrams: datagrams, qlogTrace: &events.Trace{Recorder: &recorder}}, nil)
	require.NoError(t, conn.AdvertiseRoute([]IPRoute{
		{StartIP: netip.MustParseAddr("10.0.0.0"), EndIP: netip.MustParseAddr("10.0.0.255"), IPProtocol: 17},
	}))

	hdr := &ipv4.Header{Len: ipv4.HeaderLen, TTL: 64, Protocol: 17, Src: net.IPv4(192, 0, 2, 1), Dst: net.IPv4(10, 0, 0, 1)}
	datagrams <- append(bytes.Clone(contextIDZero), marshalIPv4Header(t, hdr)...)
	hdr.Protocol = 6
	datagrams <- append(bytes.Clone(contextIDZero), marshalIPv4Header(t, hdr)...)
	hdr.Dst = net.IPv4(10, 0, 1, 1)
	datagrams <- append(bytes.Clone(contextIDZero), marshalIPv4Header(t, hdr)...)
	datagrams <- append(bytes.Clone(contextIDZero), 0x45)
	_, err := conn.ReadPacket(make([]byte, 100))
	require.NoError(t, err)
	_, err = conn.ReadPacket(make([]byte, 100))
	require.ErrorIs(t, err, io.EOF) // all remaining packets were dropped

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketProcessed{
				Source:  qlog.EndpointPeer,
				Packet:  qlogIPv4Packet(64, 17, "192.0.2.1", "10.0.0.1"),
				Outcome: qlog.PacketForwarded,
			},
			qlog.PacketProcessed{
				Source:  qlog.EndpointPeer,
				Packet:  qlogIPv4Packet(64, 6, "192.0.2.1", "10.0.0.1"),
				Outcome: qlog.PacketDropped,
				Reason:  qlog.PacketDropProtocolNotAllowed,
			},
			qlog.PacketProcessed{
				Source:  qlog.EndpointPeer,
				Packet:  qlogIPv4Packet(64, 6, "192.0.2.1", "10.0.1.1"),
				Outcome: qlog.PacketDropped,
				Reason:  qlog.PacketDropDestinationAddressNotAllowed,
			},
			qlog.PacketProcessed{
				Source:  qlog.EndpointPeer,
				Packet:  qlog.Packet{Raw: qlog.RawInfo{Length: 1, PayloadLength: qlog.OmitLength}},
				Outcome: qlog.PacketDropped,
				Reason:  qlog.PacketDropInvalid,
			},
		},
		recorder.Events(qlog.PacketProcessed{}),
	)
}

func TestQlogWritePacket(t *testing.T) {
	var recorder events.Recorder
	str := &mockStream{qlogTrace: &events.Trace{Recorder: &recorder}}
	conn := newProxiedConn(str, nil)
	require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}))

	hdr := &ipv4.Header{Len: ipv4.HeaderLen, TTL: 64, Protocol: 17, Src: net.IPv4(192, 0, 2, 1), Dst: net.IPv4(10, 0, 0, 1)}
	_, err := conn.WritePacket(marshalIPv4Header(t, hdr))
	require.NoError(t, err)
	hdr.TTL = 1
	_, err = conn.WritePacket(marshalIPv4Header(t, hdr))
	require.NoError(t, err)
	hdr.TTL = 64
	str.sendDatagramErr = &quic.DatagramTooLargeError{}
	icmp, err := conn.WritePacket(marshalIPv4Header(t, hdr))
	require.NoError(t, err)
	require.NotNil(t, icmp)

	// The TTL is logged before it is decremented.
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketProcessed{
				Source:  qlog.EndpointApplication,
				Packet:  qlogIPv4Packet(64, 17, "192.0.2.1", "10.0.0.1"),
				Outcome: qlog.PacketForwarded,
			},
			qlog.PacketProcessed{
				Source:  qlog.EndpointApplication,
				Packet:  qlogIPv4Packet(1, 17, "192.0.2.1", "10.0.0.1"),
				Outcome: qlog.PacketDropped,
				Reason:  qlog.PacketDropHopLimitExceeded,
			},
			qlog.PacketProcessed{
				Source:  qlog.EndpointApplication,
				Packet:  qlogIPv4Packet(64, 17, "192.0.2.1", "10.0.0.1"),
				Outcome: qlog.PacketDropped,
				Reason:  qlog.PacketDropTooLarge,
				ICMPResponse: &qlog.ICMPResponse{
					To: qlog.EndpointApplication,
					Packet: qlog.Packet{
						Header: qlog.IPv4Header{
							TotalLength:        48,
							TTL:                64,
							Protocol:           1,
							SourceAddress:      netip.MustParseAddr("10.0.0.1"),
							DestinationAddress: netip.MustParseAddr("192.0.2.1"),
						},
						ICMP: &qlog.ICMP{Type: 3, Code: 4, MTU: minMTU}, // Fragmentation Needed
						Raw:  qlog.RawInfo{Length: 48, PayloadLength: 28},
					},
				},
			},
		},
		recorder.Events(qlog.PacketProcessed{}),
	)
}

func TestQlogIPv6Packet(t *testing.T) {
	packet := append(composeIPv6Packet(ipProtoHopByHop, ipProtoICMPv6), 128, 0, 0, 0, 0, 0, 0, 0) // Echo Request
	binary.BigEndian.PutUint16(packet[4:6], 24)
	src, dst, ipProto, err := parseIPHeader(packet)
	require.NoError(t, err)
	require.Equal(t,
		qlog.Packet{
			Header: qlog.IPv6Header{
				PayloadLength:      24,
				NextHeader:         ipProtoHopByHop,
				HopLimit:           64,
				SourceAddress:      netip.MustParseAddr("2001:db8::1"),
				DestinationAddress: netip.MustParseAddr("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
			},
			UpperLayerProtocol: new(uint8(ipProtoICMPv6)),
			ICMP:               &qlog.ICMP{Type: 128},
			Raw:                qlog.RawInfo{Length: 64, PayloadLength: 8},
		},
		toQlogPacket(packet, src, dst, ipProto),
	)
}

func TestQlogPacketDuringClose(t *testing.T) {
	recorder := &closeTrackingRecorder{closed: make(chan struct{})}
	toRead := make(chan []byte)
	sending := make(chan struct{})
	unblock := make(chan struct{})
	conn := newProxiedConn(&mockStream{
		toRead:       toRead,
		qlogTrace:    &events.Trace{Recorder: recorder},
		sendDatagram: func([]byte) error { close(sending); <-unblock; return nil },
	}, nil)
	require.NoError(t, conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("2001:db8:85a3::/48")}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.WritePacket(bytes.Clone(ipv6Header))
	}()
	<-sending
	close(toRead) // the peer closes the stream while the packet is being sent
	select {
	case <-recorder.closed:
	case <-time.After(time.Second):
		t.Fatal("recorder wasn't closed")
	}
	close(unblock)
	<-done
	require.Empty(t, recorder.Events(qlog.PacketProcessed{}))
}
