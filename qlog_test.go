package connectip

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/connect-ip-go/qlog"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/quic-go/quic-go/testutils/events"

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
