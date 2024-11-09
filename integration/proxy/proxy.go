//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

var serverSocketRcv, serverSockedSend int

const ifaceName = "eth1"

func main() {
	bindProxyTo := netip.MustParseAddrPort(os.Getenv("BIND_PROXY_TO"))
	assignAddr := netip.MustParseAddr(os.Getenv("ASSIGN_ADDR"))
	route := netip.MustParsePrefix(os.Getenv("ROUTE"))

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get %s interface: %v", ifaceName, err)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.Fatalf("failed to get addresses for %s: %v", ifaceName, err)
	}
	if len(addrs) == 0 {
		log.Fatalf("no IPv4 addresses found for %s", ifaceName)
	}
	ethAddr, ok := netip.AddrFromSlice(addrs[0].IP)
	if !ok {
		log.Fatalf("failed to parse %s address", ifaceName)
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
	serverSockedSend = fdSnd

	if err := run(bindProxyTo, assignAddr, route); err != nil {
		log.Fatal(err)
	}
}

// This works, but we need to set the Ethernet address when sending a packet.
// works with hping3, but not with ping.
func createReceiveSocket(netip.Addr) (int, error) {
	// Create a raw IP socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	iface, err := net.InterfaceByName("eth1")
	if err != nil {
		return 0, fmt.Errorf("interface lookup failed: %w", err)
	}
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, addr); err != nil {
		log.Fatalf("Bind failed: %v", err)
	}
	return fd, nil
}

func createSendSocket(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("setting IP_HDRINCL: %w", err)
	}
	// iface, err := net.InterfaceByName("eth1")
	// if err != nil {
	// 	return 0, fmt.Errorf("Interface lookup failed: %v", err)
	// }
	sa := &unix.SockaddrInet4{
		Port: 0, // Raw sockets don't use ports
	}
	copy(sa.Addr[:], addr.AsSlice()) // Copy IP address bytes

	if err := unix.Bind(fd, sa); err != nil {
		return 0, fmt.Errorf("binding socket: %w", err)
	}
	return fd, nil
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | (host>>8)&0xff
}

func run(bindTo netip.AddrPort, remoteAddr netip.Addr, route netip.Prefix) error {
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
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := p.Proxy(w, req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := handleConn(conn, remoteAddr, route); err != nil {
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

func handleConn(conn *connectip.Conn, addr netip.Addr, route netip.Prefix) error {
	log.Printf("new connection: %#v", conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.AssignAddresses(ctx, []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}); err != nil {
		return fmt.Errorf("failed to assign addresses: %w", err)
	}
	if err := conn.AdvertiseRoute(ctx, []connectip.IPRoute{{StartIP: route.Addr(), EndIP: lastIP(route)}}); err != nil {
		return fmt.Errorf("failed to advertise route: %w", err)
	}

	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := conn.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			log.Printf("read %d bytes from connection", n)
			dest := ([4]byte)(b[16:20])
			if err := unix.Sendto(serverSockedSend, b[:n], 0, &unix.SockaddrInet4{Addr: dest}); err != nil {
				errChan <- fmt.Errorf("failed to write to server socket: %w", err)
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
			if _, err := conn.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}
