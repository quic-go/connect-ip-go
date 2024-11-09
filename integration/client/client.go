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
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	proxyPort, err := strconv.Atoi(os.Getenv("PROXY_PORT"))
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	proxyAddr := netip.AddrPortFrom(netip.MustParseAddr(os.Getenv("PROXY_ADDR")), uint16(proxyPort))
	serverAddr, err := netip.ParseAddr(os.Getenv("SERVER_ADDR"))
	if err != nil {
		log.Fatalf("failed to parse server URL: %v", err)
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
	cmd := exec.Command("tcpdump", "-i", dev.Name(), "-w", "client.pcap", "-U")
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start tcpdump: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // give tcpdump some time to start
	log.Printf("started tcpdump on TUN device: %s in the background", dev.Name())
	go proxy(ipconn, dev)

	switch os.Getenv("TESTCASE") {
	case "ping":
		if err := runPingTest(serverAddr); err != nil {
			log.Fatalf("ping test failed: %v", err)
		}
	case "http":
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		if err := runHTTPTest(tr, fmt.Sprintf("http://%s/hello", ipForURL(serverAddr))); err != nil {
			log.Fatalf("HTTP test failed: %v", err)
		}
	case "http3":
		tr := &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			QUICConfig: &quic.Config{
				InitialPacketSize: 1200,
				EnableDatagrams:   true,
			},
		}
		defer tr.Close()
		if err := runHTTPTest(tr, fmt.Sprintf("https://%s/hello", ipForURL(serverAddr))); err != nil {
			log.Fatalf("HTTP/3 test failed: %v", err)
		}
	default:
		log.Fatalf("unknown testcase: %s", os.Getenv("TESTCASE"))
	}

	time.Sleep(time.Second) // give tcpdump some time to write the last packets
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		log.Printf("failed to send SIGTERM signal to tcpdump process: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		log.Printf("tcpdump process exited with error: %v", err)
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
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
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
	log.Printf("connected to VPN server: %s", proxyAddr)

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
	if err := netlink.LinkSetMTU(link, 1280); err != nil {
		return nil, nil, fmt.Errorf("failed to set MTU: %w", err)
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

func ipForURL(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String()
	}
	return fmt.Sprintf("[%s]", addr)
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   prefix.Addr().AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
	}
}
