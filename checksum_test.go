package connectip

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
)

// taken from https://en.wikipedia.org/wiki/Internet_checksum#Calculating_the_IPv4_header_checksum
var ipv4ChecksumTestVector = [ipv4.HeaderLen]byte{
	0x45, 0x00, 0x00, 0x73,
	0x00, 0x00, 0x40, 0x00,
	0x40, 0x11, 0xb8, 0x61,
	0xc0, 0xa8, 0x00, 0x01,
	0xc0, 0xa8, 0x00, 0xc7,
}

func TestIPv4ChecksumTestVector(t *testing.T) {
	require.Equal(t, uint16(0xb861), calculateIPv4Checksum(ipv4ChecksumTestVector))
}

func TestValidateIPv4Checksum(t *testing.T) {
	header := ipv4ChecksumTestVector[:]
	withOptions := slices.Clone(header)
	withOptions[0] = 0x46                         // IHL: 6
	withOptions[10], withOptions[11] = 0xb5, 0x60 // checksum
	// three No Operation options, End of Options List
	withOptions = append(withOptions, 0x01, 0x01, 0x01, 0x00)
	invalidChecksum := slices.Clone(header)
	invalidChecksum[11]++

	for _, tt := range []struct {
		name    string
		packet  []byte
		wantErr string
	}{
		{
			name:   "valid",
			packet: header,
		},
		{
			name:   "valid, with options",
			packet: withOptions,
		},
		{
			name:   "valid, with payload",
			packet: append(slices.Clone(header), 0xde, 0xad, 0xbe, 0xef),
		},
		{
			name:    "invalid checksum",
			packet:  invalidChecksum,
			wantErr: "connect-ip: invalid IPv4 header checksum",
		},
		{
			name:    "header length exceeds packet size",
			packet:  withOptions[:20],
			wantErr: "connect-ip: invalid IPv4 header length: 24",
		},
		{
			name:    "header length too small",
			packet:  append([]byte{0x44}, header[1:]...),
			wantErr: "connect-ip: invalid IPv4 header length: 16",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPv4Checksum(tt.packet)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
