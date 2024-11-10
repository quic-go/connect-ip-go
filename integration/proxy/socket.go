//go:build linux

package main

import (
	"errors"
	"fmt"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func sendOnSocket(fd int, b []byte) error {
	switch v := ipVersion(b); v {
	case 4:
		if len(b) < ipv4.HeaderLen {
			return errors.New("IPv4 packet too short")
		}
		dest := ([4]byte)(b[16:20])
		if err := unix.Sendto(fd, b, 0, &unix.SockaddrInet4{Addr: dest}); err != nil {
			return fmt.Errorf("sendto for IPv4 packet: %w", err)
		}
		return nil
	case 6:
		if len(b) < ipv6.HeaderLen {
			return errors.New("IPv6 packet too short")
		}
		dest := ([16]byte)(b[24:40])
		if err := unix.Sendto(fd, b, 0, &unix.SockaddrInet6{Addr: dest}); err != nil {
			return fmt.Errorf("sendto for IPv6 packet: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown IP version: %d", v)
	}
}

func ipVersion(b []byte) uint8 {
	return b[0] >> 4
}
