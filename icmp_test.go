package connectip

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/stretchr/testify/require"
)

func composeICMPTooLargePacket(b []byte, mtu int) ([]byte, error) {
	return newICMPTooLargePacket(b, uint32(mtu)).Marshal()
}

func TestICMPTooLargeIPv4(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.1")
	dst := netip.MustParseAddr("8.8.8.8")

	for _, tt := range []struct {
		name      string
		packetLen int
		quoteLen  int
	}{
		{name: "small packet", packetLen: 60, quoteLen: 60},
		{name: "large packet", packetLen: 1500, quoteLen: 548},
	} {
		t.Run(tt.name, func(t *testing.T) {
			origHdr := &ipv4.Header{
				Version:  4,
				Len:      ipv4.HeaderLen,
				TotalLen: tt.packetLen,
				TTL:      64,
				Protocol: 6, // TCP
				Src:      src.AsSlice(),
				Dst:      dst.AsSlice(),
			}
			origBytes, err := origHdr.Marshal()
			require.NoError(t, err)
			// Ensure the length is in network byte order; Marshal uses native byte order on macOS.
			binary.BigEndian.PutUint16(origBytes[2:4], uint16(origHdr.TotalLen))
			for i := range origHdr.TotalLen - len(origBytes) {
				origBytes = append(origBytes, byte(i))
			}
			data, err := composeICMPTooLargePacket(origBytes, 1200)
			require.NoError(t, err)
			require.Len(t, data, ipv4.HeaderLen+8+tt.quoteLen)

			// parse the resulting IPv4 header
			hdr, err := ipv4.ParseHeader(data)
			require.NoError(t, err)
			require.Equal(t, 4, hdr.Version)
			require.Equal(t, ipProtoICMP, hdr.Protocol)
			require.Equal(t, dst.String(), hdr.Src.String())
			require.Equal(t, src.String(), hdr.Dst.String())
			require.Equal(t, uint16(hdr.Checksum), calculateIPv4Checksum(data[:ipv4.HeaderLen]))
			// parse ICMP message
			icmpMsg, err := icmp.ParseMessage(ipProtoICMP, data[ipv4.HeaderLen:])
			require.NoError(t, err)
			require.Equal(t, ipv4.ICMPTypeDestinationUnreachable, icmpMsg.Type)
			require.Equal(t, 4, icmpMsg.Code)
			icmpBody, ok := icmpMsg.Body.(*icmp.DstUnreach)
			require.True(t, ok)
			require.Equal(t, origBytes[:tt.quoteLen], icmpBody.Data)
		})
	}
}

func TestICMPTooLargeIPv6(t *testing.T) {
	const mtu = 1337
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("1:2:3:4::5")
	orig := []byte{
		0x60, 0x00, 0x00, 0x00, // Version, Traffic Class, Flow Label
		0x00, 0x00, // Payload Length
		0x00, 0x2a, // Next Header, Hop Limit (42)
	}
	orig = append(orig, src.AsSlice()...)
	orig = append(orig, dst.AsSlice()...)
	orig = append(orig, []byte("foobar")...)
	data, err := composeICMPTooLargePacket(orig, mtu)
	require.NoError(t, err)

	// parse the resulting IPv6 header
	hdr, err := ipv6.ParseHeader(data)
	require.NoError(t, err)
	require.Equal(t, 6, hdr.Version)
	require.Equal(t, ipProtoICMPv6, hdr.NextHeader)
	require.Equal(t, dst.String(), hdr.Src.String())
	require.Equal(t, src.String(), hdr.Dst.String())
	// parse ICMPv6 message
	icmpMsg, err := icmp.ParseMessage(ipProtoICMPv6, data[ipv6.HeaderLen:])
	require.NoError(t, err)
	require.Equal(t, ipv6.ICMPTypePacketTooBig, icmpMsg.Type)
	icmpBody, ok := icmpMsg.Body.(*icmp.PacketTooBig)
	require.True(t, ok)
	require.Equal(t, mtu, icmpBody.MTU)
	require.Equal(t, orig, icmpBody.Data)
}
