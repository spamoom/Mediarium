package netproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

// vpnSOCKS is a SOCKS5 proxy on the loopback address that sends connections
// through the VPN, for a FlareSolverr on this machine. Its browser then
// reaches sites from the VPN's address, so the Cloudflare pass it gets also
// works for Mediarium's own requests.
var vpnSOCKS struct {
	once sync.Once
	url  string
	err  error
}

// VPNProxyURL returns a socks5:// address on this machine that goes through
// the VPN, or "" while indexer traffic doesn't use the VPN.
func VPNProxyURL() (string, error) {
	if viaVPN(Indexers) == nil {
		return "", nil
	}
	vpnSOCKS.once.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			vpnSOCKS.err = fmt.Errorf("start the VPN proxy for FlareSolverr: %w", err)
			return
		}
		vpnSOCKS.url = "socks5://" + ln.Addr().String()
		go serveSOCKS(ln)
	})
	return vpnSOCKS.url, vpnSOCKS.err
}

func serveSOCKS(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			slog.Error("netproxy: VPN proxy stopped", "err", err)
			return
		}
		go handleSOCKS(c)
	}
}

// SOCKS5 reply codes (RFC 1928).
const (
	socksOK          = 0
	socksNotAllowed  = 2
	socksUnreachable = 3
	socksNoCommand   = 7
	socksNoAddrType  = 8
)

// handleSOCKS serves one CONNECT, without authentication. Only the VPN is
// used: with the VPN down, or for a local address, the connection is refused.
func handleSOCKS(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	addr, err := readSOCKSRequest(c)
	if err != nil {
		if code, ok := err.(socksError); ok {
			socksReply(c, byte(code))
		}
		return
	}
	src := viaVPN(Indexers)
	if src == nil || local(addr) {
		socksReply(c, socksNotAllowed)
		return
	}
	tunnel := src.Tunnel()
	if tunnel == nil {
		socksReply(c, socksUnreachable)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	up, err := tunnel.DialContext(ctx, "tcp", addr)
	cancel()
	if err != nil {
		socksReply(c, socksUnreachable)
		return
	}
	defer up.Close()
	if socksReply(c, socksOK) != nil {
		return
	}
	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

type socksError byte

func (e socksError) Error() string { return "socks error " + strconv.Itoa(int(e)) }

// readSOCKSRequest reads the greeting and the CONNECT request, and returns the
// host:port asked for.
func readSOCKSRequest(c net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", fmt.Errorf("not SOCKS5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		c.Write([]byte{5, 0xff})
		return "", fmt.Errorf("no usable auth method")
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", err
	}
	if req[0] != 5 {
		return "", fmt.Errorf("not SOCKS5")
	}
	if req[1] != 1 {
		return "", socksError(socksNoCommand)
	}
	var host string
	switch req[3] {
	case 1, 4:
		ip := make([]byte, 4)
		if req[3] == 4 {
			ip = make([]byte, 16)
		}
		if _, err := io.ReadFull(c, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", socksError(socksNoAddrType)
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
