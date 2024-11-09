package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	proxyAddr := netip.MustParseAddrPort(os.Getenv("PROXY_ADDR"))
	serverURL, err := url.Parse(os.Getenv("SERVER_ADDR"))
	if err != nil {
		log.Fatalf("failed to parse server URL: %v", err)
	}
	serverAddr, err := netip.ParseAddrPort(serverURL.Host)
	if err != nil {
		log.Fatalf("failed to parse server host: %v", err)
	}

	keyLog, err := os.Create("keys.txt")
	if err != nil {
		log.Fatalf("failed to create key log file: %v", err)
	}
	defer keyLog.Close()
	dev, ipconn, err := establishConn(proxyAddr, keyLog)
	if err != nil {
		log.Fatalf("failed to establish connection: %v", err)
	}
	go proxy(ipconn, dev)

	switch os.Getenv("TESTCASE") {
	case "ping":
		if err := runPingTest(serverAddr.Addr()); err != nil {
			log.Fatalf("ping test failed: %v", err)
		}
	case "http":
		if err := runHTTPTest(serverURL.String()); err != nil {
			log.Fatalf("HTTP test failed: %v", err)
		}
	default:
		log.Fatalf("unknown testcase: %s", os.Getenv("TESTCASE"))
	}
}

func establishConn(proxyAddr netip.AddrPort, keyLog io.Writer) (*water.Interface, *connectip.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}

	conn, err := quic.Dial(
		ctx,
		udpConn,
		&net.UDPAddr{IP: proxyAddr.Addr().AsSlice(), Port: int(proxyAddr.Port())},
		&tls.Config{
			ServerName:         "proxy",
			InsecureSkipVerify: true,
			NextProtos:         []string{http3.NextProtoH3},
			KeyLogWriter:       keyLog,
		},
		&quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(fmt.Sprintf("https://proxy:%d/vpn", proxyAddr.Port()))
	ipconn, rsp, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
	fmt.Printf("connected to VPN: %#v\n", ipconn)

	routes, err := ipconn.Routes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get routes: %w", err)
	}
	localPrefixes, err := ipconn.LocalPrefixes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get local prefixes: %w", err)
	}

	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	log.Printf("created TUN device: %s", dev.Name())

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}
	for _, prefix := range localPrefixes {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixToIPNet(prefix)}); err != nil {
			return nil, nil, fmt.Errorf("failed to add address assigned by peer %s: %w", prefix, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	for _, route := range routes {
		log.Printf("adding routes for %s - %s (protocol: %d)", route.StartIP, route.EndIP, route.IPProtocol)
		for _, prefix := range route.Prefixes() {
			r := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       prefixToIPNet(prefix),
			}
			if err := netlink.RouteAdd(r); err != nil {
				return nil, nil, fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
	return dev, ipconn, nil
}

func proxy(ipconn *connectip.Conn, dev *water.Interface) error {
	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := ipconn.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			log.Printf("Read %d bytes from connection", n)
			if _, err := dev.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to TUN: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
			n, err := dev.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from TUN: %w", err)
				return
			}
			log.Printf("read %d bytes from TUN", n)
			if _, err := ipconn.Write(b[:n]); err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	dev.Close()
	ipconn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}
