package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetWriteDeadline(time.Time) error
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

// If a packet is too large to fit into a QUIC datagram,
// we send an ICMP Packet Too Big packet.
// On IPv6, the minimum MTU of a link is 1280 bytes.
const minMTU = 1280

// Bound pending capsules in both directions. Queues only grow when the peer
// falls behind reading the stream or the application falls behind receiving updates.
const maxQueuedCapsules = 128

type streamWrite struct {
	Data []byte
	Fin  bool
}

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str         http3Stream
	closeConn   func() error
	writeNotify chan struct{}
	writeDone   chan error

	assignedAddressUpdates  chan []AssignedAddress
	addressRequests         chan *addressRequestCapsule
	availableRouteUpdates   chan []IPRoute
	dnsConfigurationUpdates chan []DNSConfiguration
	pref64Updates           chan []netip.Prefix

	mu                   sync.Mutex
	queuedWrites         []streamWrite
	peerAddresses        []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes          []IPRoute      // IP routes that we advertised to the peer
	assignedAddresses    []netip.Prefix // IP prefixes that the peer assigned to us
	peerRoutes           []IPRoute      // IP routes that the peer advertised to us
	lastAddressRequestID AddressRequestID

	closeChan chan struct{}
	closeErr  error
}

func newProxiedConn(str http3Stream, closeConn func() error) *Conn {
	c := &Conn{
		str:                     str,
		closeConn:               closeConn,
		writeNotify:             make(chan struct{}, 1),
		writeDone:               make(chan error, 1),
		assignedAddressUpdates:  make(chan []AssignedAddress, maxQueuedCapsules),
		addressRequests:         make(chan *addressRequestCapsule, maxQueuedCapsules),
		availableRouteUpdates:   make(chan []IPRoute, 1),
		dnsConfigurationUpdates: make(chan []DNSConfiguration, 1),
		pref64Updates:           make(chan []netip.Prefix, 1),
		closeChan:               make(chan struct{}),
	}
	go func() {
		err := c.readFromStream()
		if err != nil {
			log.Printf("handling stream failed: %v", err)
		}
		c.mu.Lock()
		if c.closeErr == nil {
			c.closeErr = &CloseError{Remote: true}
			close(c.closeChan)
			if err != nil {
				// Abort without consuming the remaining capsule payload.
				c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				close(c.writeNotify)
			} else {
				_ = c.queueWrite(streamWrite{Fin: true})
			}
		}
		c.mu.Unlock()
	}()
	go func() {
		err := c.writeToStream()
		if err != nil {
			log.Printf("writing to stream failed: %v", err)
			c.mu.Lock()
			if c.closeErr == nil {
				c.closeErr = &CloseError{Remote: true}
				close(c.closeChan)
				c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
			} else {
				// A write can time out while graceful shutdown is pending.
				c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
			}
			c.mu.Unlock()
		}
		c.writeDone <- err
		close(c.writeDone)
	}()
	return c
}

// AdvertiseRoute schedules an advertisement of the available routes to the peer.
// It returns once the advertisement has been queued.
func (c *Conn) AdvertiseRoute(routes []IPRoute) error {
	if err := validateRouteAdvertisement(routes); err != nil {
		return err
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	routes = slices.Clone(routes)
	err := c.queueWrite(streamWrite{Data: (&routeAdvertisementCapsule{IPAddressRanges: routes}).append(nil)})
	if err == nil {
		c.localRoutes = routes
	}
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

// RequestAddresses requests address prefixes from the peer and returns once the
// request is queued. It allocates a unique, nonzero ID for each prefix in input order.
// The IDs have no semantic meaning and can be used to correlate assignments
// returned by [Conn.ReceiveAddressAssignment] with the requested prefixes.
//
// Prefixes must be valid, with all bits outside the prefix set to zero.
// An unspecified address (0.0.0.0 or ::) requests any address of that family,
// with the prefix length indicating the preferred size.
func (c *Conn) RequestAddresses(prefixes []netip.Prefix) ([]AddressRequestID, error) {
	if len(prefixes) == 0 {
		return nil, errors.New("connect-ip: address request must contain at least one prefix")
	}
	for i, p := range prefixes {
		if !p.IsValid() || p != p.Masked() {
			return nil, fmt.Errorf("connect-ip: invalid requested prefix %d: %s", i, p)
		}
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return nil, err
	}
	ids := make([]AddressRequestID, len(prefixes))
	for i := range ids {
		ids[i] = c.lastAddressRequestID + AddressRequestID(i) + 1
	}
	capsule := &addressRequestCapsule{RequestIDs: ids, Prefixes: prefixes}
	err := c.queueWrite(streamWrite{Data: capsule.append(nil)})
	if err == nil {
		c.lastAddressRequestID = ids[len(ids)-1]
	}
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return ids, nil
}

// ReceiveAddressAssignment waits for the next complete address assignment,
// Each assignment replaces the preceding one; request IDs only provide optional correlation.
// Call this method in a loop from one goroutine.
func (c *Conn) ReceiveAddressAssignment(ctx context.Context) ([]AssignedAddress, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case assignment := <-c.assignedAddressUpdates:
		return assignment, nil
	case <-c.closeChan:
		// Deliver queued responses before reporting closure.
		select {
		case assignment := <-c.assignedAddressUpdates:
			return assignment, nil
		default:
			return nil, c.closeErr
		}
	}
}

// ReceiveAddressRequest waits for the next address request from the peer.
// This method should be called in a loop, and each request should be answered with [AddressRequest.Respond].
func (c *Conn) ReceiveAddressRequest(ctx context.Context) (*AddressRequest, error) {
	var requested *addressRequestCapsule
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case requested = <-c.addressRequests:
	case <-c.closeChan:
		select {
		case requested = <-c.addressRequests:
		default:
			return nil, c.closeErr
		}
	}
	return newAddressRequest(c, requested), nil
}

// AssignAddresses schedules an assignment of address prefixes to the peer.
// A nil or empty slice removes all assigned addresses.
func (c *Conn) AssignAddresses(prefixes []netip.Prefix) error {
	capsule := &addressAssignCapsule{
		AssignedAddresses: make([]AssignedAddress, len(prefixes)),
	}
	for i, p := range prefixes {
		capsule.AssignedAddresses[i] = AssignedAddress{IPPrefix: p}
	}
	return c.sendAddressAssignment(capsule)
}

func (c *Conn) sendAddressAssignment(capsule *addressAssignCapsule) error {
	for i, addr := range capsule.AssignedAddresses {
		p := addr.IPPrefix
		if !p.IsValid() || p != p.Masked() {
			return fmt.Errorf("connect-ip: invalid assigned prefix %d: %s", i, p)
		}
	}

	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	if err := c.queueWrite(streamWrite{Data: capsule.append(nil)}); err != nil {
		c.mu.Unlock()
		_ = c.Close()
		return err
	}

	// Keep an empty assignment distinct from not having sent one.
	prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
	for _, assigned := range capsule.AssignedAddresses {
		if !assigned.Rejected() {
			prefixes = append(prefixes, assigned.IPPrefix)
		}
	}
	c.peerAddresses = prefixes
	c.mu.Unlock()
	return nil
}

// SendDNSConfiguration schedules a DNS configuration update to the peer.
// The update supersedes the DNS configuration previously sent on this connection.
//
// To avoid leaking DNS traffic outside the tunnel, the application is responsible
// for advertising the corresponding routes before calling this method. See
// [Section 5 of draft-ietf-masque-connect-ip-dns-06].
//
// [Section 5 of draft-ietf-masque-connect-ip-dns-06]: https://datatracker.ietf.org/doc/html/draft-ietf-masque-connect-ip-dns-06#section-5
func (c *Conn) SendDNSConfiguration(configurations []DNSConfiguration) error {
	for _, config := range configurations {
		if err := config.validate(); err != nil {
			return fmt.Errorf("invalid DNS configuration: %w", err)
		}
	}
	return c.sendCapsule((&dnsAssignCapsule{DNSConfigurations: configurations}).append(nil))
}

// ReceiveDNSConfiguration waits for the next DNS configuration update from the peer.
// Each update supersedes the preceding one.
func (c *Conn) ReceiveDNSConfiguration(ctx context.Context) ([]DNSConfiguration, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case configurations := <-c.dnsConfigurationUpdates:
		return configurations, nil
	}
}

// SendPREF64Configuration schedules an update of the NAT64 prefixes to use for
// IPv6/IPv4 address synthesis. It returns once the update has been queued. An
// empty slice clears the previously sent configuration.
func (c *Conn) SendPREF64Configuration(prefixes []netip.Prefix) error {
	for i, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid NAT64 prefix %d: not an IPv6 prefix", i)
		}
		switch prefix.Bits() {
		case 32, 40, 48, 56, 64, 96:
		default:
			return fmt.Errorf("invalid NAT64 prefix %d: invalid prefix length %d", i, prefix.Bits())
		}
	}
	return c.sendCapsule((&pref64Capsule{Prefixes: prefixes}).append(nil))
}

// ReceivePREF64Configuration waits for the next NAT64 prefix update from the
// peer. An empty slice means that NAT64 prefixes are not available.
func (c *Conn) ReceivePREF64Configuration(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case prefixes := <-c.pref64Updates:
		return prefixes, nil
	}
}

func (c *Conn) sendCapsule(capsuleData []byte) error {
	c.mu.Lock()
	if c.closeErr != nil {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	err := c.queueWrite(streamWrite{Data: capsuleData})
	c.mu.Unlock()
	if err != nil {
		_ = c.Close()
		return err
	}
	return nil
}

func (c *Conn) queueWrite(w streamWrite) error {
	if w.Fin {
		// Interrupt pending capsule writes so shutdown cannot stall.
		_ = c.str.SetWriteDeadline(time.Now())
	} else if len(c.queuedWrites) >= maxQueuedCapsules {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
		c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
		c.str.CancelWrite(quic.StreamErrorCode(http3.ErrCodeExcessiveLoad))
		close(c.writeNotify)
		return errors.New("connect-ip: capsule queue full")
	}

	c.queuedWrites = append(c.queuedWrites, w)

	select {
	case c.writeNotify <- struct{}{}:
	default:
	}
	return nil
}

func queueLatest[T any](ch chan T, value T) {
	for {
		select {
		case ch <- value:
			return
		case <-ch:
		}
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case routes := <-c.availableRouteUpdates:
		return routes, nil
	}
}

func (c *Conn) readFromStream() error {
	p := http3.NewCapsuleParser(c.str)
	for {
		t, cr, err := p.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
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
				if !assigned.Rejected() {
					prefixes = append(prefixes, assigned.IPPrefix)
				}
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.mu.Unlock()
			select {
			case c.assignedAddressUpdates <- capsule.AssignedAddresses:
			default:
				return errors.New("connect-ip: address assignment queue full")
			}
		case capsuleTypeAddressRequest:
			capsule, err := parseAddressRequestCapsule(cr)
			if err != nil {
				return err
			}
			select {
			case c.addressRequests <- capsule:
			default:
				return errors.New("connect-ip: address request queue full")
			}
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			// Store the routes first, so that WritePacket can send to them once Routes returns them.
			c.mu.Lock()
			c.peerRoutes = slices.Clone(capsule.IPAddressRanges)
			c.mu.Unlock()
			queueLatest(c.availableRouteUpdates, capsule.IPAddressRanges)
		case capsuleTypeDNSAssign:
			capsule, err := parseDNSAssignCapsule(cr)
			if err != nil {
				return err
			}
			queueLatest(c.dnsConfigurationUpdates, capsule.DNSConfigurations)
		case capsuleTypePREF64:
			capsule, err := parsePREF64Capsule(cr)
			if err != nil {
				return err
			}
			queueLatest(c.pref64Updates, capsule.Prefixes)
		default:
			if err := cr.Discard(); err != nil {
				return err
			}
		}
	}
}

func (c *Conn) writeToStream() error {
	for range c.writeNotify {
		for {
			c.mu.Lock()
			if len(c.queuedWrites) == 0 {
				c.mu.Unlock()
				break
			}
			w := c.queuedWrites[0]
			c.queuedWrites[0] = streamWrite{}
			c.queuedWrites = c.queuedWrites[1:]
			c.mu.Unlock()

			if w.Fin {
				return c.str.Close()
			}
			if _, err := c.str.Write(w.Data); err != nil {
				return err
			}
		}
	}
	return c.closeErr
}

func (c *Conn) ReadPacket(b []byte) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		select {
		case <-c.closeChan:
			return 0, c.closeErr
		default:
			return 0, err
		}
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
	src, dst, ipProto, err := parseIPHeader(data)
	if err != nil {
		return err
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
	if !isAllowedDestination(dst, ipProto, assignedAddresses, localRoutes) {
		// TODO: send ICMP
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

// WritePacket writes an IP packet to the stream.
// The packet is dropped unless its destination was assigned to the peer or matches one of the peer's routes.
// If the peer assigned addresses to us, the source address needs to be one of these addresses,
// or be covered by one of the routes that we advertised.
// If sending the packet fails, it might return an ICMP packet.
// It is the caller's responsibility to send the ICMP packet to the sender.
func (c *Conn) WritePacket(b []byte) (icmp []byte, err error) {
	// The stream's send side is closed asynchronously,
	// so it might still accept datagrams after the connection was closed.
	select {
	case <-c.closeChan:
		return nil, c.closeErr
	default:
	}

	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil, nil
	}
	if err := c.str.SendDatagram(data); err != nil {
		if _, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			icmpPacket, err := composeICMPTooLargePacket(b, minMTU)
			if err != nil {
				log.Printf("failed to compose ICMP too large packet: %s", err)
			}
			return icmpPacket, nil
		}
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	src, dst, ipProto, err := parseIPHeader(b)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	assignedAddresses := c.assignedAddresses
	localRoutes := c.localRoutes
	peerAddresses := c.peerAddresses
	peerRoutes := c.peerRoutes
	c.mu.Unlock()

	// The source IP address is valid if
	// 1. the peer didn't assign any addresses to us, or
	// 2. it is within one of the ranges assigned to us, or
	// 3. it is within one of the ranges that we advertised to the peer (independent of the IP protocol),
	//    since we're forwarding packets from these networks.
	if assignedAddresses != nil &&
		!slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) &&
		!slices.ContainsFunc(localRoutes, func(r IPRoute) bool { return r.contains(src) }) {
		return nil, fmt.Errorf("connect-ip: source address not allowed: %s", src)
	}
	// The destination IP address is valid if it
	// 1. is within one of the ranges that we assigned to the peer, or
	// 2. is within one of the ranges that the peer advertised to us.
	if !isAllowedDestination(dst, ipProto, peerAddresses, peerRoutes) {
		return nil, fmt.Errorf("connect-ip: destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}

	switch ipVersion(b) {
	case 4:
		ttl := b[8]
		if ttl <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		b[8]-- // decrement TTL
		// recalculate the checksum
		hdrLen := int(b[0]&0x0f) * 4
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(b[:hdrLen]))
	case 6:
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

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
		_ = c.queueWrite(streamWrite{Fin: true})
	}
	closeConn := c.closeConn
	c.closeConn = nil
	c.mu.Unlock()
	err := <-c.writeDone
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	if closeConn != nil {
		return errors.Join(err, closeConn())
	}
	return err
}
