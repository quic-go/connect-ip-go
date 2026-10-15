package qlog

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/stretchr/testify/require"
)

type nopWriteCloserImpl struct{ io.Writer }

func (nopWriteCloserImpl) Close() error { return nil }

func nopWriteCloser(w io.Writer) io.WriteCloser {
	return &nopWriteCloserImpl{Writer: w}
}

func testEventEncoding(t *testing.T, ev qlogwriter.Event) (string, string) {
	t.Helper()
	var buf bytes.Buffer

	synctest.Test(t, func(t *testing.T) {
		tr := qlogwriter.NewConnectionFileSeq(
			nopWriteCloser(&buf),
			true,
			quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4}),
			EventSchemas,
		)
		go tr.Run()
		producer := tr.AddProducer()

		synctest.Wait()
		time.Sleep(42 * time.Second)

		producer.RecordEvent(ev)
		producer.Close()
	})

	return decode(t, buf.String())
}

func decode(t *testing.T, data string) (string, string) {
	t.Helper()

	var result struct {
		Time float64
		Name string
		Data json.RawMessage
	}

	lines := bytes.Split([]byte(data), []byte{'\n'})
	require.Len(t, lines, 3) // the first line is the trace header, the second line is the event, the third line is empty
	require.Empty(t, lines[2])
	require.NotEmpty(t, lines[1])
	require.Equal(t, qlogwriter.RecordSeparator, lines[1][0], "expected record separator at start of line")
	require.NoError(t, json.Unmarshal(lines[1][1:], &result))
	require.Equal(t, 42*time.Second, time.Duration(result.Time*1e6)*time.Nanosecond)

	return result.Name, string(result.Data)
}

func TestCapsuleCreatedEvent(t *testing.T) {
	name, ev := testEventEncoding(t, CapsuleCreated{
		StreamID: quic.StreamID(4),
		Capsule: Capsule{Capsule: PREF64Capsule{
			Prefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")},
			Raw:      RawInfo{Length: 18, PayloadLength: 13},
		}},
	})

	require.Equal(t, "http:capsule_created", name)
	require.JSONEq(t, `{
		"stream_id": 4,
		"capsule": {
			"capsule_type": "pref64",
			"prefixes": ["64:ff9b::/96"],
			"raw": {
				"length": 18,
				"payload_length": 13
			}
		}
	}`, ev)
}

func TestCapsuleParsedEvent(t *testing.T) {
	name, ev := testEventEncoding(t, CapsuleParsed{
		StreamID: quic.StreamID(8),
		Capsule: Capsule{Capsule: AddressAssignCapsule{
			AssignedAddresses: []Address{{RequestID: 1, IPPrefix: netip.MustParsePrefix("192.0.2.1/32")}},
			Raw:               RawInfo{Length: 9, PayloadLength: 7},
		}},
	})

	require.Equal(t, "http:capsule_parsed", name)
	require.JSONEq(t, `{
		"stream_id": 8,
		"capsule": {
			"capsule_type": "address_assign",
			"assigned_addresses": [
				{"request_id": 1, "ip_prefix": "192.0.2.1/32"}
			],
			"raw": {
				"length": 9,
				"payload_length": 7
			}
		}
	}`, ev)
}
