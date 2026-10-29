package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestHTTPSRedirectDoesNotDiscloseDestinationToken(t *testing.T) {
	var referer string
	var redirected bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "source.fixture.net" {
			http.Redirect(w, r, "https://destination.fixture.net/", http.StatusFound)
			return
		}
		redirected = true
		referer = r.Header.Get("Referer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c := Checker{
		Resolver: publicResolver,
		RootCAs:  &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12},
		Dial: func(ctx context.Context, network, pinned string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
	got := c.Check(context.Background(), "https://source.fixture.net/private?jwt=SYNTHETIC_CREDENTIAL#title")
	if got.Verdict != Healthy || !redirected || referer != "" {
		t.Fatalf("healthy=%v redirected=%v referer_empty=%v", got.Verdict == Healthy, redirected, referer == "")
	}
}

func TestSpecialUseIPv6NeverReachesDial(t *testing.T) {
	for _, address := range []string{
		"64:ff9b::a00:1", "64:ff9b:1::a00:1", "100::1", "fe80::1%eth0",
		"2001::1", "2001:100::1", "2001:db8::1", "2002:a00:1::1", "3fff::1",
	} {
		t.Run(address, func(t *testing.T) {
			called := false
			c := Checker{
				Resolver: func(context.Context, string) ([]netip.Addr, error) {
					return []netip.Addr{netip.MustParseAddr(address)}, nil
				},
				Dial: func(context.Context, string, string) (net.Conn, error) {
					called = true
					return nil, errors.New("unexpected dial")
				},
			}
			got := c.Check(context.Background(), "https://source.fixture.net/")
			if called || got.Verdict != Uncertain {
				t.Fatalf("dial=%v verdict=%v", called, got.Verdict)
			}
		})
	}
}
