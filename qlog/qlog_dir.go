package qlog

import (
	"context"

	"github.com/quic-go/quic-go"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
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

// EventSchemas are the qlog event schemas used by connect-ip-go.
// Applications that construct their own qlog tracer should list these schemas,
// in addition to the QUIC and HTTP/3 event schemas used by quic-go.
var EventSchemas = []string{EventSchemaHTTP, EventSchemaConnectIP, EventSchemaConnectIPDNS}

// DefaultConnectionTracer creates a qlog file in the qlog directory specified by the QLOGDIR environment variable.
// File names are <odcid>_<perspective>.sqlog.
// Returns nil if QLOGDIR is not set.
func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(
		ctx,
		isClient,
		connID,
		append([]string{qlog.EventSchema, h3qlog.EventSchema}, EventSchemas...),
	)
}
