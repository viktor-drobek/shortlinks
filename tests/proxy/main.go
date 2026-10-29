// Command proxy verifies the reverse-proxy boundary with a synthetic identity provider.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func run() error {
	image := os.Getenv("CADDY_TEST_IMAGE")
	if image == "" {
		image = "caddy:2"
	}
	docker := os.Getenv("DOCKER_BIN")
	if docker == "" {
		docker = "docker"
	}
	fixtureKey := "reverse-proxy-fixture-only"
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "unavailable" {
			w.WriteHeader(503)
			return
		}
		if token == "forbidden" {
			w.WriteHeader(403)
			return
		}
		if token == "" || token == r.Header.Get("Authorization") {
			w.WriteHeader(401)
			return
		}
		if token != "missing-user" {
			w.Header().Set("X-Auth-Request-User", "fixture-user")
		}
		switch token {
		case "member", "missing-user":
			w.Header().Set("X-Auth-Request-Groups", "/links")
		case "multiple":
			w.Header().Set("X-Auth-Request-Groups", "/other,/links")
		case "similar":
			w.Header().Set("X-Auth-Request-Groups", "/links-admin")
		case "child":
			w.Header().Set("X-Auth-Request-Groups", "/links/child")
		}
		w.WriteHeader(202)
	}))
	defer auth.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Shortlinks-Proxy-Key") != fixtureKey {
			w.WriteHeader(502)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Auth-Request-User") != "fixture-user" {
			w.WriteHeader(502)
			return
		}
		if len(r.URL.Path) == 9 && r.Header.Get("X-Auth-Request-User") != "" {
			w.WriteHeader(502)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			w.WriteHeader(502)
			return
		}
		w.WriteHeader(200)
	}))
	defer backend.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := ln.Addr().String()
	if err = ln.Close(); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "shortlinks-proxy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	source, err := os.ReadFile("deploy/Caddyfile")
	if err != nil {
		return err
	}
	text := "{\n admin off\n auto_https off\n}\n" + string(source)
	text = strings.ReplaceAll(text, "{$SHORTLINKS_HOST:s.2050.su} {", "http://"+address+" {")
	text = strings.ReplaceAll(text, "{$SHORTLINKS_HOST:s.2050.su}", address)
	text = strings.ReplaceAll(text, "{$SHORTLINKS_UPSTREAM:shortlinks:8080}", strings.TrimPrefix(backend.URL, "http://"))
	text = strings.ReplaceAll(text, "{$SHORTLINKS_AUTH_UPSTREAM:oauth2-proxy:4180}", strings.TrimPrefix(auth.URL, "http://"))
	text = strings.ReplaceAll(text, "{$SHORTLINKS_PROXY_KEY}", fixtureKey)
	config := filepath.Join(dir, "Caddyfile")
	// The file contains synthetic credentials only. Its private parent directory
	// protects it on the host; the cap-dropped container needs read access.
	if err = os.WriteFile(config, []byte(text), 0o444); err != nil { // #nosec G306 G703 -- generated fixed basename in private os.MkdirTemp directory; synthetic fixture configuration only.
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// A private host-network fixture uses only dynamically allocated loopback ports.
	name := fmt.Sprintf("shortlinks-proxy-fixture-%d", time.Now().UnixNano())
	// #nosec G204 G702 -- operator-selected fixture executable, fixed argv, no shell or request input.
	cmd := exec.CommandContext(ctx, docker, "run", "--rm", "--name", name, "--network", "host", "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-v", config+":/etc/caddy/Caddyfile:ro", image, "caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile")
	var diagnostics bytes.Buffer
	cmd.Stdout = &diagnostics
	cmd.Stderr = &diagnostics
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("fixture process did not start")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		// #nosec G204 G702 -- operator-selected fixture executable and generated container name, no shell or request input.
		stop := exec.CommandContext(cleanupCtx, docker, "rm", "-f", name)
		stop.Stdout = io.Discard
		stop.Stderr = io.Discard
		_ = stop.Run()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for i := 0; i < 100; i++ {
		response, e := client.Get("http://" + address + "/healthz")
		if e == nil {
			if e = response.Body.Close(); e != nil {
				return fmt.Errorf("fixture health body close failed")
			}
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		select {
		case e = <-done:
			return fmt.Errorf("fixture exited before readiness: %v\n%.4096s", e, diagnostics.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return fmt.Errorf("fixture readiness failed")
	}
	tests := []struct {
		name, path, token, accept string
		spoof                     bool
		want                      int
	}{
		{"public", "/aB3xY7kQ", "", "", false, 200},
		{"public-spoof-stripped", "/aB3xY7kQ", "member", "", true, 200},
		{"api-anonymous", "/api/v1/links", "", "", false, 401},
		{"api-spoof", "/api/v1/links", "", "", true, 401},
		{"api-no-group", "/api/v1/links", "no-group", "", false, 403},
		{"api-similar-group", "/api/v1/links", "similar", "", false, 403},
		{"api-child-group", "/api/v1/links", "child", "", false, 403},
		{"api-missing-user", "/api/v1/links", "missing-user", "", false, 403},
		{"api-member", "/api/v1/links", "member", "", false, 200},
		{"api-multiple", "/api/v1/links", "multiple", "", false, 200},
		{"browser-login", "/manage", "", "text/html", false, 302},
		{"browser-forbidden", "/manage", "forbidden", "text/html", false, 403},
		{"auth-unavailable", "/api/v1/links", "unavailable", "", false, 503},
	}
	for _, tt := range tests {
		req, e := http.NewRequest(http.MethodGet, "http://"+address+tt.path, nil)
		if e != nil {
			return fmt.Errorf("test request failed")
		}
		if tt.token != "" {
			req.Header.Set("Authorization", "Bearer "+tt.token)
		}
		if tt.accept != "" {
			req.Header.Set("Accept", tt.accept)
		}
		if tt.spoof {
			req.Header.Set("X-Auth-Request-User", "forged")
			req.Header.Set("X-Auth-Request-Groups", "/links")
			req.Header.Set("X-Shortlinks-Proxy-Key", fixtureKey)
			req.Header.Set("X-Forwarded-User", "forged")
		}
		resp, e := client.Do(req)
		if e != nil {
			return fmt.Errorf("%s: request failed", tt.name)
		}
		if err = resp.Body.Close(); err != nil {
			return fmt.Errorf("%s response body close failed", tt.name)
		}
		if resp.StatusCode != tt.want {
			return fmt.Errorf("%s: got %d want %d", tt.name, resp.StatusCode, tt.want)
		}
		fmt.Printf("PASS %s\n", tt.name)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
