package connectip

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIPv4ChecksumTestVector(t *testing.T) {
	// taken from https://en.wikipedia.org/wiki/Internet_checksum#Calculating_the_IPv4_header_checksum
	data := []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7}
	checksum := calculateIPv4Checksum(data)
	require.Equal(t, uint16(0xb861), checksum)

	// make sure that too short inputs are rejected
	require.Zero(t, calculateIPv4Checksum(data[:10]))
}
