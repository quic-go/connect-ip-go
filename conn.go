package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type appendable interface{ append([]byte) []byte }

type writeCapsule struct {
	capsule appendable
	result  chan error
}

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str    http3.Stream
	writes chan writeCapsule

	assignedAddressNotify chan struct{}
	availableRoutesNotify chan struct{}

	mu                sync.Mutex
	peerAddresses     []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes       []IPRoute      // IP routes that we advertised to the peer
	assignedAddresses []netip.Prefix
	availableRoutes   []IPRoute
}

func newProxiedConn(str http3.Stream) *Conn {
	c := &Conn{
		str:                   str,
		writes:                make(chan writeCapsule),
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
	}
	go func() {
		if err := c.readFromStream(); err != nil {
			log.Printf("handling stream failed: %v", err)
		}
	}()
	go func() {
		if err := c.writeToStream(); err != nil {
			log.Printf("writing to stream failed: %v", err)
		}
	}()
	return c
}

// AdvertiseRoute informs the peer about available routes.
// This function can be called multiple times, but only the routes from the most recent call will be active.
// Previous route advertisements are overwritten by each new call to this function.
func (c *Conn) AdvertiseRoute(ctx context.Context, routes []IPRoute) error {
	for _, route := range routes {
		if route.StartIP.Compare(route.EndIP) == 1 {
			return fmt.Errorf("invalid route advertising start_ip: %s larger than %s", route.StartIP, route.EndIP)
		}
	}
	c.mu.Lock()
	c.localRoutes = slices.Clone(routes)
	c.mu.Unlock()
	return c.sendCapsule(ctx, &routeAdvertisementCapsule{IPAddressRanges: routes})
}

// AssignAddresses assigned address prefixes to the peer.
// This function can be called multiple times, but only the addresses from the most recent call will be active.
// Previous address assignments are overwritten by each new call to this function.
func (c *Conn) AssignAddresses(ctx context.Context, prefixes []netip.Prefix) error {
	c.mu.Lock()
	c.peerAddresses = slices.Clone(prefixes)
	c.mu.Unlock()
	capsule := &addressAssignCapsule{AssignedAddresses: make([]AssignedAddress, 0, len(prefixes))}
	for _, p := range prefixes {
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	return c.sendCapsule(ctx, capsule)
}

func (c *Conn) sendCapsule(ctx context.Context, capsule appendable) error {
	res := make(chan error, 1)
	select {
	case c.writes <- writeCapsule{
		capsule: capsule,
		result:  res,
	}:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-res:
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LocalPrefixes returns the prefixes that the peer currently assigned.
// Note that at any point during the connection, the peer can change the assignment.
// It is therefore recommended to call this function in a loop.
func (c *Conn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.assignedAddressNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.assignedAddresses, nil
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.availableRoutesNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.availableRoutes, nil
	}
}

func (c *Conn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		t, cr, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				prefixes = append(prefixes, assigned.IPPrefix)
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.mu.Unlock()
			select {
			case c.assignedAddressNotify <- struct{}{}:
			default:
			}
		case capsuleTypeAddressRequest:
			if _, err := parseAddressRequestCapsule(cr); err != nil {
				return err
			}
			return errors.New("connect-ip: address request not yet supported")
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			c.mu.Lock()
			c.availableRoutes = capsule.IPAddressRanges
			c.mu.Unlock()
			select {
			case c.availableRoutesNotify <- struct{}{}:
			default:
			}
		default:
			return fmt.Errorf("unknown capsule type: %d", t)
		}
	}
}

func (c *Conn) writeToStream() error {
	buf := make([]byte, 0, 1024)
	for {
		req, ok := <-c.writes
		if !ok {
			return nil
		}
		buf = req.capsule.append(buf[:0])
		_, err := c.str.Write(buf)
		req.result <- err
		if err != nil {
			return err
		}
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, err
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		// TODO: close connection
		return 0, fmt.Errorf("connect-ip: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of IP payloads.
		goto start
	}
	if err := c.handleIncomingProxiedPacket(data[n:]); err != nil {
		log.Printf("dropping proxied packet: %s", err)
		goto start
	}
	return copy(b, data[n:]), nil
}

func (c *Conn) handleIncomingProxiedPacket(data []byte) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch v := ipVersion(data); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		ipProto = data[9]
	case 6:
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		ipProto = data[6]
	}

	c.mu.Lock()
	assignedAddresses := c.assignedAddresses
	localRoutes := c.localRoutes
	peerAddresses := c.peerAddresses
	c.mu.Unlock()

	// We don't necessarily assign any addresses to the peer.
	// For example, in the Remote Access VPN use case (RFC 9484, section 8.1),
	// the client accepts incoming traffic from all IPs.
	if peerAddresses != nil {
		if !slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
			// TODO: send ICMP
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	// The destination IP address is valid if it
	// 1. is within one of the ranges assigned to us, or
	// 2. is within one of the ranges that we advertised to the peer.
	var isAllowedDst bool
	if len(assignedAddresses) > 0 {
		isAllowedDst = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(dst) })
	}
	if !isAllowedDst {
		isAllowedDst = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
				return false
			}
			// TODO: walk the chain of IPv6 extensions
			// See section 4.8 of RFC 9484 for details.
			return ipProto == 0 || r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if !isAllowedDst {
		// TODO: send ICMP
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return 0, nil
	}
	return len(b), c.str.SendDatagram(data)
}

func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	// TODO: implement src, dst and ipproto checks
	if len(b) == 0 {
		return nil, nil
	}
	switch v := ipVersion(b); v {
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		ttl := b[8]
		if ttl <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		b[8]-- // decrement TTL
		// recalculate the checksum
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(([ipv4.HeaderLen]byte)(b[:ipv4.HeaderLen])))
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		hopLimit := b[7]
		if hopLimit <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", hopLimit)
		}
		b[7]-- // Decrement Hop Limit
	}
	data := make([]byte, 0, len(contextIDZero)+len(b))
	data = append(data, contextIDZero...)
	data = append(data, b...)
	return data, nil
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }
