package checker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

var fakePublic = netip.MustParseAddr("8.8.8.8")

func fixtureChecker(t *testing.T, handler http.Handler, resolver Resolver) Checker {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	_, localPort, err := net.SplitHostPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return Checker{
		Resolver: resolver,
		Dial: func(ctx context.Context, network, pinned string) (net.Conn, error) {
			// Assert the checker passed a pinned, public DNS result to its
			// dialer; only this test adapter sends it to the local fixture.
			host, _, err := net.SplitHostPort(pinned)
			if err != nil {
				return nil, err
			}
			if host != fakePublic.String() {
				return nil, errors.New("not pinned fake public IP")
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", localPort))
		},
	}
}

func publicResolver(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{fakePublic}, nil
}

func TestCheckHealthyAndHeaderOnly(t *testing.T) {
	var gotMethod, gotRange string
	c := fixtureChecker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotRange = r.Method, r.Header.Get("Range")
		w.WriteHeader(http.StatusNoContent)
	}), publicResolver)
	got := c.Check(context.Background(), "http://healthy.fixture.net/")
	if got.Verdict != Healthy {
		t.Fatalf("verdict = %+v", got)
	}
	if gotMethod != http.MethodHead {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotRange != "" {
		t.Fatalf("unexpected Range for header-only request: %q", gotRange)
	}
}

func TestCheck404IsMissing(t *testing.T) {
	c := fixtureChecker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }), publicResolver)
	if got := c.Check(context.Background(), "http://missing.fixture.net/"); got.Verdict != Missing {
		t.Fatalf("got %+v", got)
	}
}

func TestCheckOtherStatusIsUncertain(t *testing.T) {
	c := fixtureChecker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }), publicResolver)
	if got := c.Check(context.Background(), "http://denied.fixture.net/"); got.Verdict != Uncertain {
		t.Fatalf("got %+v", got)
	}
}

func TestCheckBlocksMixedDNSAnswerBeforeDial(t *testing.T) {
	called := false
	c := Checker{
		Resolver: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{fakePublic, netip.MustParseAddr("127.0.0.1")}, nil
		},
		Dial: func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil },
	}
	got := c.Check(context.Background(), "http://mixed.fixture.net/")
	if got.Verdict != Uncertain || got.Reason != "ssrf blocked" {
		t.Fatalf("got %+v", got)
	}
	if called {
		t.Fatal("dialled a mixed DNS answer")
	}
}

func TestCheckBlocksReservedIPs(t *testing.T) {
	for _, address := range []string{"169.254.169.254", "192.168.1.1", "2001:db8::1", "fc00::1"} {
		t.Run(address, func(t *testing.T) {
			c := Checker{Resolver: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr(address)}, nil
			}}
			got := c.Check(context.Background(), "http://blocked.fixture.net/")
			if got.Verdict != Uncertain || got.Reason != "ssrf blocked" {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestValidateURLBlocksMappedIPv6Literal(t *testing.T) {
	if err := validateURL("http://[::ffff:8.8.8.8]/"); err == nil {
		t.Fatal("accepted IPv4-mapped IPv6 literal")
	}
}

func TestCheckPinsDNSOnEveryRedirect(t *testing.T) {
	var mu sync.Mutex
	lookups := make(map[string]int)
	c := fixtureChecker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "first.fixture.net" {
			http.Redirect(w, r, "http://second.fixture.net/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		lookups[host]++
		mu.Unlock()
		return []netip.Addr{fakePublic}, nil
	})
	got := c.Check(context.Background(), "http://first.fixture.net/")
	if got.Verdict != Healthy {
		t.Fatalf("got %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if lookups["first.fixture.net"] != 1 || lookups["second.fixture.net"] != 1 {
		t.Fatalf("lookups = %#v", lookups)
	}
}

func TestCheckRedirectLimitIsUncertain(t *testing.T) {
	c := fixtureChecker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		step, _ := strconv.Atoi(r.URL.Query().Get("n"))
		http.Redirect(w, r, "http://loop.fixture.net/?n="+strconv.Itoa(step+1), http.StatusFound)
	}), publicResolver)
	got := c.Check(context.Background(), "http://loop.fixture.net/?n=0")
	if got.Verdict != Uncertain || got.Reason != "redirect limit" {
		t.Fatalf("got %+v", got)
	}
}

func TestClassifyErrors(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		verdict Verdict
	}{
		{"dns", errDNS, Uncertain},
		{"blocked", errBlocked, Uncertain},
		{"timeout", context.DeadlineExceeded, Uncertain},
		{"tls", &url.Error{Err: errors.New("x509: certificate signed by unknown authority")}, Uncertain},
		{"eof", io.EOF, Missing},
		{"unexpected eof", io.ErrUnexpectedEOF, Missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyError(context.Background(), tc.err)
			if got.Verdict != tc.verdict {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestURLValidation(t *testing.T) {
	for _, raw := range []string{
		"ftp://public.fixture.net/", "http://user@public.fixture.net/", "http://localhost/",
		"http://127.0.0.1/", "http://public.fixture.net:8080/", "http://public.fixture.net/\r\nX: y",
	} {
		if err := validateURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"http://public.fixture.net/", "https://public.fixture.net/"} {
		if err := validateURL(raw); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
}

func TestCallerCancellationIsUncertain(t *testing.T) {
	c := Checker{Resolver: func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := c.Check(ctx, "http://cancel.fixture.net/")
	if got.Verdict != Uncertain || got.Reason != "context cancelled" {
		t.Fatalf("got %+v", got)
	}
}

func TestNoEnvironmentProxy(t *testing.T) {
	// A proxy environment variable must not matter: the injected direct
	// dialer serves this request. Save and restore process environment.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	c := fixtureChecker(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }), publicResolver)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got := c.Check(ctx, "http://proxy-ignore.fixture.net/"); got.Verdict != Healthy {
		t.Fatalf("got %+v", got)
	}
}
