package qlog

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/quic-go/quic-go"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlog"

	"github.com/stretchr/testify/require"
)

func TestQLOGDIRSet(t *testing.T) {
	tmpDir := t.TempDir()

	connID := quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4})
	qlogDir := filepath.Join(tmpDir, "qlogs")
	t.Setenv("QLOGDIR", qlogDir)

	tracer := DefaultConnectionTracer(context.Background(), true, connID)
	require.NotNil(t, tracer)
	for _, schema := range EventSchemas {
		require.True(t, tracer.SupportsSchemas(schema))
	}

	// adding and closing a producer makes the tracer close the file
	recorder := tracer.AddProducer()
	recorder.Close()

	require.DirExists(t, qlogDir)

	entries, err := os.ReadDir(qlogDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	data, err := os.ReadFile(filepath.Join(qlogDir, entries[0].Name()))
	require.NoError(t, err)

	require.Contains(t, string(data), qlog.EventSchema)
	require.Contains(t, string(data), h3qlog.EventSchema)
	require.Contains(t, string(data), EventSchemaHTTP)
	require.Contains(t, string(data), EventSchemaConnectIP)
	require.Contains(t, string(data), EventSchemaConnectIPDNS)
}

func TestQLOGDIRNotSet(t *testing.T) {
	t.Setenv("QLOGDIR", "")
	require.Nil(t, DefaultConnectionTracer(context.Background(), true, quic.ConnectionIDFromBytes([]byte{1, 2, 3, 4})))
}
