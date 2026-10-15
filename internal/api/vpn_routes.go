package api

import (
	"net"
	"net/url"
	"strings"

	"github.com/rdborg/mediarium/internal/netproxy"
	"github.com/rdborg/mediarium/internal/settings"
	"github.com/rdborg/mediarium/internal/vpn"
)

// vpnRoute lets netproxy send traffic through the VPN without knowing about
// the VPN package.
type vpnRoute struct{ m *vpn.Manager }

func (r vpnRoute) Tunnel() netproxy.ContextDialer {
	// Check for a nil *Tunnel before converting to the interface, or a nil
	// pointer would look like a real tunnel.
	if t := r.m.Tunnel(); t != nil {
		return t
	}
	return nil
}

func (r vpnRoute) Selected() (label, reason string) {
	st := r.m.Status()
	return st.Label, st.Reason
}

// vpnForIndexers reports whether indexer traffic is set to go through the VPN.
func (s *Server) vpnForIndexers() bool {
	v, _ := s.Settings.GetBool(settings.KeyVPNRouteIndexers)
	return v
}

// applyVPNRoutes tells netproxy which traffic goes through the VPN. Torrents
// aren't part of it: the torrent engine is handed the tunnel itself (see
// torrentTunnel).
func (s *Server) applyVPNRoutes() {
	netproxy.SetVPN(vpnRoute{s.VPNManager}, map[netproxy.Use]bool{netproxy.Indexers: s.vpnForIndexers()})
}

// flareSolverrOnVPN reports whether FlareSolverr's browser goes through the
// VPN too. Only one on this machine can reach the VPN proxy, which listens on
// the loopback address.
func (s *Server) flareSolverrOnVPN() bool {
	return s.vpnForIndexers() && onThisMachine(s.flareSolverrURL())
}

// onThisMachine reports whether raw is an address on the loopback interface.
func onThisMachine(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

// flareSolverrProxy is the proxy handed to FlareSolverr, so sites behind a
// Cloudflare check see the VPN's address and its pass works for Mediarium too.
func (s *Server) flareSolverrProxy() (string, error) {
	if !s.flareSolverrOnVPN() {
		return "", nil
	}
	return netproxy.VPNProxyURL()
}
