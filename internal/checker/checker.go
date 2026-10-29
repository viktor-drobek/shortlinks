// Package checker checks a short-link destination without trusting DNS or
// proxies. It is independent from storage and HTTP handlers.
package checker

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Verdict string

const (
	Healthy   Verdict = "healthy"
	Missing   Verdict = "missing"
	Uncertain Verdict = "uncertain"
)

type Result struct {
	Verdict Verdict
	Reason  string
}

const (
	requestTimeout = 10 * time.Second
	maxRedirects   = 5
)

// Resolver is injectable so tests never make an external DNS request.
type Resolver func(context.Context, string) ([]netip.Addr, error)

// DialContext is passed a validated, DNS-pinned IP address and port.
type DialContext func(context.Context, string, string) (net.Conn, error)

// Checker checks URLs. Its zero value uses the system resolver, direct TCP,
// and normal TLS certificate verification.
type Checker struct {
	Resolver Resolver
	Dial     DialContext
	RootCAs  *tls.Config // Test-only hook: only RootCAs/ServerName are copied.
}

// Check checks a URL using the production defaults.
func Check(ctx context.Context, rawURL string) Result { return (Checker{}).Check(ctx, rawURL) }

// Check checks a URL using the configured resolver and dialer.
func (c Checker) Check(ctx context.Context, rawURL string) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateURL(rawURL); err != nil {
		return uncertain("blocked url")
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	tr := &http.Transport{
		Proxy:             nil,  // Never honor HTTP_PROXY, HTTPS_PROXY, or NO_PROXY.
		DisableKeepAlives: true, // Force a fresh pinned resolution per hop.
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return c.dialPinned(ctx, network, address)
		},
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig:     c.tlsConfig(),
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Go otherwise adds the previous bearer URL as the Referer.
			req.Header.Del("Referer")
			if len(via) >= maxRedirects {
				return errRedirectLimit
			}
			if err := validateURL(req.URL.String()); err != nil {
				return errBlocked
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return uncertain("invalid request")
	}
	req.Header.Set("User-Agent", "shortlinks-checker/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return classifyError(ctx, err)
	}
	if err := resp.Body.Close(); err != nil { // HEAD is header-only; do not fetch destination content.
		return uncertain("response close failure")
	}

	if resp.StatusCode == http.StatusNotFound {
		return missing("http 404")
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return healthy("http 2xx")
	}
	return uncertain("non-success status")
}

func (c Checker) dialPinned(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errBlocked
	}
	ips, err := c.lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errDNS
	}
	ip, err := pinnedIP(ips)
	if err != nil {
		return nil, err
	}
	if c.Dial != nil {
		return c.Dial(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

func (c Checker) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if c.Resolver != nil {
		return c.Resolver(ctx, host)
	}
	answers, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return answers, nil
}

func (c Checker) tlsConfig() *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.RootCAs != nil {
		cfg.RootCAs = c.RootCAs.RootCAs
		cfg.ServerName = c.RootCAs.ServerName
	}
	return cfg
}

var (
	errDNS           = errors.New("dns failure")
	errBlocked       = errors.New("ssrf blocked")
	errRedirectLimit = errors.New("redirect limit")
)

func classifyError(ctx context.Context, err error) Result {
	if errors.Is(ctx.Err(), context.Canceled) {
		return uncertain("context cancelled")
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return uncertain("timeout")
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		err = uerr.Err
	}
	switch {
	case errors.Is(err, errDNS):
		return uncertain("dns failure")
	case errors.Is(err, errBlocked):
		return uncertain("ssrf blocked")
	case errors.Is(err, errRedirectLimit):
		return uncertain("redirect limit")
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return missing("connection eof")
	case errors.Is(err, syscall.ECONNRESET):
		return missing("connection reset")
	}
	var tlsErr tls.RecordHeaderError
	if errors.As(err, &tlsErr) || strings.Contains(strings.ToLower(err.Error()), "tls") || strings.Contains(strings.ToLower(err.Error()), "x509") {
		return uncertain("tls failure")
	}
	return uncertain("request failure")
}

func healthy(reason string) Result   { return Result{Verdict: Healthy, Reason: reason} }
func missing(reason string) Result   { return Result{Verdict: Missing, Reason: reason} }
func uncertain(reason string) Result { return Result{Verdict: Uncertain, Reason: reason} }

// pinnedIP rejects an entire answer if any record is not public global
// unicast. This prevents mixed-answer bypasses. It sorts valid records so a
// rebinding-resistant dial target is deterministic.
func pinnedIP(ips []netip.Addr) (netip.Addr, error) {
	if len(ips) == 0 {
		return netip.Addr{}, errDNS
	}
	valid := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Zone() != "" || ip.Is4In6() || !publicIP(net.IP(ip.AsSlice())) {
			return netip.Addr{}, errBlocked
		}
		valid = append(valid, ip)
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Less(valid[j]) })
	return valid[0], nil
}

func bytesLess(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func publicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return publicIPv4(v4)
	}
	v6 := ip.To16()
	// Only the currently allocated global-unicast block is eligible. This
	// excludes local NAT64/translation, discard-only, and future-use ranges.
	if v6 == nil || v6[0]&0xe0 != 0x20 || isIPv4Mapped(v6) {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	// Exclude the IETF special-purpose block 2001::/23, documentation
	// 2001:db8::/32 and 3fff::/20, and the 6to4 transition block 2002::/16.
	if (v6[0] == 0x20 && v6[1] == 0x01 && (v6[2] < 2 || (v6[2] == 0x0d && v6[3] == 0xb8))) ||
		(v6[0] == 0x20 && v6[1] == 0x02) || (v6[0] == 0x3f && v6[1] == 0xff && v6[2]&0xf0 == 0) {
		return false
	}
	return true
}

func isIPv4Mapped(v6 net.IP) bool { return allZero(v6[:10]) && v6[10] == 0xff && v6[11] == 0xff }
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func publicIPv4(ip net.IP) bool {
	a, b, c := ip[0], ip[1], ip[2]
	switch {
	case a == 0 || a == 10 || a == 127 || a >= 224:
		return false
	case a == 100 && b >= 64 && b <= 127: // shared address space
		return false
	case a == 169 && b == 254:
		return false
	case a == 172 && b >= 16 && b <= 31:
		return false
	case a == 192 && (b == 0 || b == 168 || (b == 0 && c == 2) || (b == 88 && c == 99)):
		return false
	case a == 198 && ((b >= 18 && b <= 19) || (b == 51 && c == 100)):
		return false
	case a == 203 && b == 0 && c == 113:
		return false
	}
	return true
}

func validateURL(raw string) error {
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return errBlocked
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" {
		return errBlocked
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || (p != 80 && p != 443) {
		return errBlocked
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is4In6() || !publicIP(net.IP(ip.AsSlice())) {
			return errBlocked
		}
		return nil
	}
	for _, suffix := range []string{"localhost", ".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet", ".private", ".test", ".invalid", ".example", ".onion"} {
		if host == suffix || strings.HasSuffix(host, suffix) {
			return errBlocked
		}
	}
	return nil
}
