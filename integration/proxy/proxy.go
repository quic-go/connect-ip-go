//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/connect-ip-go/integration/internal/utils"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

var serverSocketRcv, serverSocketSend int

var ifaceName = os.Getenv("SERVER_INTERFACE")

func main() {
	proxyPort, err := strconv.Atoi(os.Getenv("PROXY_PORT"))
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	bindProxyTo := netip.AddrPortFrom(netip.MustParseAddr(os.Getenv("PROXY_ADDR")), uint16(proxyPort))

	assignAddr := netip.MustParseAddr(os.Getenv("ASSIGN_ADDR"))
	route := netip.MustParsePrefix(os.Getenv("ROUTE"))
	ipProtocol, err := strconv.ParseUint(os.Getenv("FILTER_IP_PROTOCOL"), 10, 8)
	if err != nil {
		log.Fatalf("failed to parse FILTER_IP_PROTOCOL: %v", err)
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get %s interface: %v", ifaceName, err)
	}
	family := netlink.FAMILY_V4
	if assignAddr.Is6() {
		family = netlink.FAMILY_V6
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		log.Fatalf("failed to get addresses for %s: %v", ifaceName, err)
	}
	if len(addrs) == 0 {
		log.Fatalf("no IP addresses found for %s", ifaceName)
	}
	var ethAddr netip.Addr
	for _, addr := range addrs {
		a, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			log.Fatalf("failed to parse %s address", ifaceName)
		}
		if !a.IsLinkLocalUnicast() {
			ethAddr = a
			break
		}
	}

	fdRcv, err := createReceiveSocket(ethAddr)
	if err != nil {
		log.Fatalf("failed to create receive socket: %v", err)
	}
	serverSocketRcv = fdRcv

	fdSnd, err := createSendSocket(ethAddr)
	if err != nil {
		log.Fatalf("failed to create send socket: %v", err)
	}
	serverSocketSend = fdSnd

	if err := run(bindProxyTo, assignAddr, route, uint8(ipProtocol)); err != nil {
		log.Fatal(err)
	}
}

func createReceiveSocket(a netip.Addr) (int, error) {
	proto := unix.ETH_P_IP
	if a.Is6() {
		proto = unix.ETH_P_IPV6
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(uint16(proto))))
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, fmt.Errorf("interface lookup failed: %w", err)
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(uint16(proto)),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		log.Fatalf("Bind failed: %v", err)
	}
	return fd, nil
}

func createSendSocket(addr netip.Addr) (int, error) {
	if addr.Is4() {
		return createSendSocketIPv4(addr)
	}
	return createSendSocketIPv6(addr)
}

func createSendSocketIPv4(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("setting IP_HDRINCL: %w", err)
	}
	sa := &unix.SockaddrInet4{Port: 0} // raw sockets don't use ports
	copy(sa.Addr[:], addr.AsSlice())
	if err := unix.Bind(fd, sa); err != nil {
		return 0, fmt.Errorf("binding socket to %s: %w", addr, err)
	}
	return fd, nil
}

func createSendSocketIPv6(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("setting IPV6_HDRINCL: %w", err)
	}
	sa := &unix.SockaddrInet6{Port: 0} // raw sockets don't use ports
	copy(sa.Addr[:], addr.AsSlice())
	if err := unix.Bind(fd, sa); err != nil {
		return 0, fmt.Errorf("binding socket to %s: %w", addr, err)
	}
	return fd, nil
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | (host>>8)&0xff
}

func run(bindTo netip.AddrPort, remoteAddr netip.Addr, route netip.Prefix, ipProtocol uint8) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindTo.Addr().AsSlice(), Port: int(bindTo.Port())})
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	template := uritemplate.MustNew(fmt.Sprintf("https://proxy:%d/vpn", bindTo.Port()))
	ln, err := quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		&quic.Config{EnableDatagrams: true},
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	defer ln.Close()

	p := connectip.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		req, err := connectip.ParseRequest(r, template)
		if err != nil {
			var perr *connectip.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := p.Proxy(w, req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := handleConn(conn, remoteAddr, route, ipProtocol); err != nil {
			log.Printf("failed to handle connection: %v", err)
		}
	})
	s := http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}
	go s.ServeListener(ln)
	defer s.Close()

	select {}
}

func handleConn(conn *connectip.Conn, addr netip.Addr, route netip.Prefix, ipProtocol uint8) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.AssignAddresses(ctx, []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}); err != nil {
		return fmt.Errorf("failed to assign addresses: %w", err)
	}
	if err := conn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{StartIP: route.Addr(), EndIP: utils.LastIP(route), IPProtocol: ipProtocol},
	}); err != nil {
		return fmt.Errorf("failed to advertise route: %w", err)
	}

	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := conn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			log.Printf("read %d bytes from connection", n)
			if err := sendOnSocket(serverSocketSend, b[:n]); err != nil {
				errChan <- fmt.Errorf("writing to server socket: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
			n, _, err := unix.Recvfrom(serverSocketRcv, b, 0)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from server socket: %w", err)
				return
			}
			log.Printf("read %d bytes from %s", n, ifaceName)
			icmp, err := conn.WritePacket(b[:n])
			if err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
			if len(icmp) > 0 {
				if err := sendOnSocket(serverSocketSend, icmp); err != nil {
					log.Printf("failed to send ICMP packet: %v", err)
				}
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}
