// Command oidc runs an isolated oauth2-proxy bearer-token integration fixture.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	clientID = "shortlinks-web"
	group    = "/links"
)

type issuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	jwks   []byte
}

func newIssuer() (*issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate fixture signing key: %w", err)
	}
	jwk, err := json.Marshal(map[string]string{
		"kty": "RSA",
		"kid": "fixture-key",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal fixture JWK: %w", err)
	}
	result := &issuer{key: key}
	result.jwks, err = json.Marshal(map[string]json.RawMessage{"keys": json.RawMessage("[" + string(jwk) + "]")})
	if err != nil {
		return nil, fmt.Errorf("marshal fixture JWKS: %w", err)
	}
	result.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"userinfo_endpoint":%q}`, result.server.URL, result.server.URL+"/authorize", result.server.URL+"/token", result.server.URL+"/jwks", result.server.URL+"/userinfo")))
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(result.jwks)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return result, nil
}

func (i *issuer) token(audience string, groups []string, invalidSignature bool) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "fixture-key", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss":                i.server.URL,
		"sub":                "fixture-user",
		"preferred_username": "fixture-user",
		"email":              "fixture@example.test",
		"aud":                audience,
		"exp":                time.Now().Add(time.Minute).Unix(),
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"groups":             groups,
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(payload))
	key := i.key
	if invalidSignature {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return payload + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func freeLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return address, nil
}

func fixtureConfig(address, issuerURL string) string {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(err)
	}
	cookieSecret := base64.RawURLEncoding.EncodeToString(random[:])
	return fmt.Sprintf(`provider = "oidc"
client_id = %q
client_secret = %q
redirect_url = "http://%s/oauth2/callback"
scope = "openid profile"
email_domains = ["*"]
oidc_email_claim = "preferred_username"
oidc_groups_claim = "groups"
oidc_issuer_url = %q
insecure_oidc_allow_unverified_email = true
allowed_groups = ["%s"]
http_address = %q
upstreams = ["static://202"]
set_xauthrequest = true
pass_access_token = false
pass_authorization_header = false
pass_basic_auth = false
pass_user_headers = false
skip_jwt_bearer_tokens = true
bearer_token_login_fallback = false
cookie_secret = %q
cookie_secure = false
request_logging = false
auth_logging = false
standard_logging = false
silence_ping_logging = true
`, clientID, cookieSecret, address, issuerURL, group, address, cookieSecret)
}

func dockerBinary() string {
	if docker := os.Getenv("DOCKER_BIN"); docker != "" {
		return docker
	}
	return "docker"
}

func proxyImage() string {
	if image := os.Getenv("OAUTH2_PROXY_TEST_IMAGE"); image != "" {
		return image
	}
	return "quay.io/oauth2-proxy/oauth2-proxy:v7.15.4-alpine" // gitleaks:allow -- public container image tag, not a credential.
}

func waitReady(client *http.Client, address string, done <-chan error) error {
	for range 100 {
		response, err := client.Get("http://" + address + "/ready")
		if err == nil {
			closeErr := response.Body.Close()
			if closeErr != nil {
				return fmt.Errorf("fixture readiness body close: %w", closeErr)
			}
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case err := <-done:
			return fmt.Errorf("oauth2-proxy exited before readiness: %w", err)
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("oauth2-proxy readiness timed out")
}

func assertAuth(client *http.Client, address, name, token string, wantStatus int, wantHeaders bool) error {
	req, err := http.NewRequest(http.MethodGet, "http://"+address+"/oauth2/auth", nil)
	if err != nil {
		return fmt.Errorf("%s request construction: %w", name, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request: %w", name, err)
	}
	if err := response.Body.Close(); err != nil {
		return fmt.Errorf("%s response body close: %w", name, err)
	}
	if response.StatusCode != wantStatus {
		return fmt.Errorf("%s: got HTTP %d, want HTTP %d", name, response.StatusCode, wantStatus)
	}
	if wantHeaders && (response.Header.Get("X-Auth-Request-User") != "fixture-user" || response.Header.Get("X-Auth-Request-Groups") != group) {
		return fmt.Errorf("%s: required identity response headers were not set", name)
	}
	if !wantHeaders && (response.Header.Get("X-Auth-Request-User") != "" || response.Header.Get("X-Auth-Request-Groups") != "") {
		return fmt.Errorf("%s: identity response headers were unexpectedly set", name)
	}
	fmt.Printf("PASS %s\n", name)
	return nil
}

func run() error {
	issuer, err := newIssuer()
	if err != nil {
		return err
	}
	defer issuer.server.Close()
	address, err := freeLoopbackAddress()
	if err != nil {
		return fmt.Errorf("allocate loopback address: %w", err)
	}
	dir, err := os.MkdirTemp("", "shortlinks-oidc-")
	if err != nil {
		return fmt.Errorf("create fixture directory: %w", err)
	}
	defer os.RemoveAll(dir)
	config := filepath.Join(dir, "oauth2-proxy.cfg")
	if err := os.WriteFile(config, []byte(fixtureConfig(address, issuer.server.URL)), 0644); err != nil { // #nosec G306 -- public synthetic OIDC fixture data inside private os.MkdirTemp directory, readable by unprivileged fixture container.
		return fmt.Errorf("write fixture configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	name := fmt.Sprintf("shortlinks-oidc-fixture-%d", time.Now().UnixNano())
	var diagnostics bytes.Buffer
	// #nosec G204 G702 -- DOCKER_BIN is a fixture-operator executable override; argv has no request input.
	command := exec.CommandContext(ctx, dockerBinary(), "run", "--pull=never", "--rm", "--name", name, "--network", "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-v", config+":/etc/oauth2-proxy.cfg:ro", proxyImage(), "--config=/etc/oauth2-proxy.cfg")
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		return errors.New("oauth2-proxy fixture process did not start")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		// #nosec G204 -- DOCKER_BIN is a fixture-operator executable override; container name is generated.
		cleanup := exec.CommandContext(cleanupCtx, dockerBinary(), "rm", "-f", name)
		cleanup.Stdout = io.Discard
		cleanup.Stderr = io.Discard
		_ = cleanup.Run()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	if err := waitReady(client, address, done); err != nil {
		return err
	}
	member, err := issuer.token(clientID, []string{group}, false)
	if err != nil {
		return fmt.Errorf("create member token: %w", err)
	}
	wrongGroup, err := issuer.token(clientID, []string{"/other"}, false)
	if err != nil {
		return fmt.Errorf("create wrong-group token: %w", err)
	}
	wrongAudience, err := issuer.token("other-client", []string{group}, false)
	if err != nil {
		return fmt.Errorf("create wrong-audience token: %w", err)
	}
	badSignature, err := issuer.token(clientID, []string{group}, true)
	if err != nil {
		return fmt.Errorf("create bad-signature token: %w", err)
	}
	for _, test := range []struct {
		name, token string
		status      int
		headers     bool
	}{
		{name: "member-token", token: member, status: http.StatusAccepted, headers: true},
		{name: "wrong-group", token: wrongGroup, status: http.StatusUnauthorized},
		{name: "wrong-audience", token: wrongAudience, status: http.StatusForbidden},
		{name: "bad-signature", token: badSignature, status: http.StatusForbidden},
		{name: "absent-credentials", status: http.StatusUnauthorized},
	} {
		if err := assertAuth(client, address, test.name, test.token, test.status, test.headers); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
