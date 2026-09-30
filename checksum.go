package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/net/ipv4"
)

func calculateIPv4Checksum(header [ipv4.HeaderLen]byte) uint16 {
	// add every 16-bit word in the header, skipping the checksum field (bytes 10 and 11)
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue // skip checksum field
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// validateIPv4Checksum checks the header checksum of an IPv4 packet, including options.
// The packet must be at least ipv4.HeaderLen bytes long.
func validateIPv4Checksum(b []byte) error {
	hdrLen := int(b[0]&0x0f) * 4
	if hdrLen < ipv4.HeaderLen || hdrLen > len(b) {
		return fmt.Errorf("connect-ip: invalid IPv4 header length: %d", hdrLen)
	}
	var sum uint32
	for i := 0; i < hdrLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if sum != 0xffff {
		return errors.New("connect-ip: invalid IPv4 header checksum")
	}
	return nil
}
