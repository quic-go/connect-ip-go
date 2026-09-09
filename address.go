package connectip

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
)

var (
	rejectedIPv4Prefix = netip.PrefixFrom(netip.IPv4Unspecified(), 32)
	rejectedIPv6Prefix = netip.PrefixFrom(netip.IPv6Unspecified(), 128)
)

// AddressRequestID identifies an address request. Zero denotes an unsolicited assignment.
type AddressRequestID uint64

// AddressRequest is a request received from the peer.
// The zero value is not valid.
type AddressRequest struct {
	Prefixes []netip.Prefix

	conn      *Conn
	requested *addressRequestCapsule
	// Use a pointer so copies of the request cannot be answered independently.
	responded *atomic.Bool
}

func newAddressRequest(conn *Conn, requested *addressRequestCapsule) *AddressRequest {
	return &AddressRequest{
		Prefixes:  slices.Clone(requested.Prefixes),
		conn:      conn,
		requested: requested,
		responded: &atomic.Bool{},
	}
}

// Respond queues the complete address assignment for the peer.
// Assignments must have one entry per original requested prefix, in the same order.
// A zero-value netip.Prefix rejects that request.
// Additional contains any other valid prefixes to include, with request ID zero.
// All prefixes must have their host bits cleared.
// A request can be answered only once.
func (r *AddressRequest) Respond(assignments, additional []netip.Prefix) error {
	if r.conn == nil {
		return errors.New("connect-ip: invalid address request")
	}
	if len(assignments) != len(r.requested.RequestIDs) {
		return fmt.Errorf(
			"connect-ip: expected %d address assignments, got %d",
			len(r.requested.RequestIDs),
			len(assignments),
		)
	}
	capsule := &addressAssignCapsule{
		AssignedAddresses: make([]AssignedAddress, 0, len(assignments)+len(additional)),
	}
	var zeroPrefix netip.Prefix
	for i, p := range assignments {
		if p == zeroPrefix {
			if r.requested.Prefixes[i].Addr().Is4() {
				p = rejectedIPv4Prefix
			} else {
				p = rejectedIPv6Prefix
			}
		} else if !p.IsValid() || p != p.Masked() {
			return fmt.Errorf("connect-ip: invalid assigned prefix %d: %s", i, p)
		}
		capsule.AssignedAddresses = append(
			capsule.AssignedAddresses,
			AssignedAddress{RequestID: r.requested.RequestIDs[i], IPPrefix: p},
		)
	}
	for i, p := range additional {
		if !p.IsValid() || p != p.Masked() {
			return fmt.Errorf("connect-ip: invalid additional prefix %d: %s", i, p)
		}
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	// claim the response after validation, so invalid inputs can be retried
	if !r.responded.CompareAndSwap(false, true) {
		return errors.New("connect-ip: address request already answered")
	}
	if err := r.conn.sendAddressAssignment(capsule); err != nil {
		r.responded.Store(false)
		return err
	}
	return nil
}
