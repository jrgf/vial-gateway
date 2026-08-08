package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vialconfig "github.com/jrgf/go-vial/config"
)

type upstreamRequest struct {
	Method        string         `json:"method"`
	Path          string         `json:"path"`
	Body          map[string]any `json:"body"`
	RequestID     string         `json:"request_id"`
	ForwardedFor  string         `json:"forwarded_for"`
	ForwardedHost string         `json:"forwarded_host"`
}

func TestDynamicGateway(t *testing.T) {
	first, firstHits := newTestUpstream(t, "first", false)
	second, secondHits := newTestUpstream(t, "second", false)
	configuration := testApplicationConfig([]string{first.URL, second.URL})
	app, err := newApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	server := httptest.NewServer(app)
	defer server.Close()

	request := func(method, path, body string, authenticated bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if authenticated {
			req.Header.Set(apiKeyHeader, "test-api-key-1234")
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	t.Run("health and metrics", func(t *testing.T) {
		if err := app.manager.readiness(context.Background()); err != nil {
			t.Fatalf("data-plane readiness: %v", err)
		}
		for _, path := range []string{"/health/live", "/metrics"} {
			response := request(http.MethodGet, path, "", false)
			_ = response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				t.Fatalf("%s returned %d", path, response.StatusCode)
			}
		}
	})

	t.Run("authentication and scopes", func(t *testing.T) {
		response := request(http.MethodGet, "/api/users", "", false)
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d", response.StatusCode)
		}
		if firstHits.Load()+secondHits.Load() != 0 {
			t.Fatal("unauthorized request reached an upstream")
		}
	})

	t.Run("rewrite transforms and forwarding", func(t *testing.T) {
		response := request(http.MethodPost, "/api/users?expand=roles", `{"name":"Ada","remove":"me"}`, true)
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d: %s", response.StatusCode, readText(response.Body))
		}
		var got upstreamRequest
		if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Path != "/users" || got.Method != http.MethodPost {
			t.Fatalf("unexpected upstream request: %+v", got)
		}
		if got.Body["tenant"] != "gateway" {
			t.Fatalf("request transform missing: %+v", got.Body)
		}
		if _, exists := got.Body["remove"]; exists {
			t.Fatalf("request transform did not remove key: %+v", got.Body)
		}
		if got.RequestID == "" || got.ForwardedFor == "" || got.ForwardedHost == "" {
			t.Fatalf("forwarding headers missing: %+v", got)
		}
	})

	t.Run("round robin", func(t *testing.T) {
		for range 4 {
			response := request(http.MethodGet, "/api/users", "", true)
			_ = response.Body.Close()
		}
		if firstHits.Load() == 0 || secondHits.Load() == 0 {
			t.Fatalf("hits first=%d second=%d", firstHits.Load(), secondHits.Load())
		}
	})

	t.Run("CORS", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodOptions, server.URL+"/api/users", nil)
		req.Header.Set("Origin", "https://client.example")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusNoContent || response.Header.Get("Access-Control-Allow-Origin") != "https://client.example" {
			t.Fatalf("unexpected CORS response: %d %q", response.StatusCode, response.Header.Get("Access-Control-Allow-Origin"))
		}
	})

	t.Run("body limit", func(t *testing.T) {
		response := request(http.MethodPost, "/api/users", `{"value":"`+strings.Repeat("x", 1<<16)+`"}`, true)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d", response.StatusCode)
		}
	})

	t.Run("atomic reload keeps last good", func(t *testing.T) {
		replacement := configuration.Gateway
		replacement.Version = 2
		replacement.Routes[0].PathPrefix = "/v2"
		if err := app.manager.Activate(replacement); err != nil {
			t.Fatal(err)
		}
		response := request(http.MethodGet, "/v2/users", "", true)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("reloaded status = %d", response.StatusCode)
		}

		invalid := replacement
		invalid.Version = 3
		invalid.Routes = append(invalid.Routes, invalid.Routes[0])
		invalid.Routes[1].Name = "conflict"
		if err := app.manager.Activate(invalid); err == nil {
			t.Fatal("conflicting reload succeeded")
		}
		if got := app.manager.current.Load().config.Version; got != 2 {
			t.Fatalf("active version = %d, want 2", got)
		}
	})
}

func TestIdempotentRetry(t *testing.T) {
	upstream, hits := newTestUpstream(t, "flaky", true)
	configuration := testApplicationConfig([]string{upstream.URL})
	configuration.Gateway.Routes[0].Retries = 1
	app, err := newApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	server := httptest.NewServer(app)
	defer server.Close()
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/api/retry", nil)
	req.Header.Set(apiKeyHeader, "test-api-key-1234")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || hits.Load() != 2 {
		t.Fatalf("status=%d hits=%d", response.StatusCode, hits.Load())
	}
}

func TestRewriteUpstreamRedirects(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		location string
		want     string
	}{
		{name: "root relative", enabled: true, location: "/onboard?step=1#profile", want: "/homar/onboard?step=1#profile"},
		{name: "same upstream absolute", enabled: true, location: "http://hub.lab.lan/app/login", want: "/homar/login"},
		{name: "external", enabled: true, location: "https://login.example/authorize", want: "https://login.example/authorize"},
		{name: "disabled", location: "/onboard", want: "/onboard"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := &compiledRoute{config: routeConfig{PathPrefix: "/homar", PathRewrite: "/app", RewriteRedirects: test.enabled}}
			response := &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{test.location}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    httptest.NewRequest(http.MethodGet, "http://hub.lab.lan/app/current", nil),
			}
			recorder := httptest.NewRecorder()
			route.writeResponse(recorder, httptest.NewRequest(http.MethodGet, "http://gateway.example/homar/current", nil), response, "")
			if got := recorder.Header().Get("Location"); got != test.want {
				t.Fatalf("Location = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReloadGatewayRetainsLastGoodState(t *testing.T) {
	upstream, _ := newTestUpstream(t, "reload", false)
	configuration := testApplicationConfig([]string{upstream.URL})
	app, err := newApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	currentCertificate := &tls.Certificate{}
	certificates := &certificateReloader{}
	certificates.current.Store(currentCertificate)
	replacement := configuration
	replacement.Gateway.Version = 2
	replacement.Gateway.Routes[0].PathPrefix = "/replacement"
	replacement.TLS = tlsConfig{CertFile: "/missing/certificate.pem", KeyFile: "/missing/key.pem"}

	if err := reloadGateway(app, certificates, replacement); err == nil {
		t.Fatal("reload with an invalid certificate succeeded")
	}
	if app.manager.current.Load().config.Version != configuration.Gateway.Version {
		t.Fatal("invalid certificate changed the active router")
	}
	if certificates.current.Load() != currentCertificate {
		t.Fatal("invalid certificate replaced the active certificate")
	}

	replacement.TLS = tlsConfig{}
	if err := reloadGateway(app, certificates, replacement); err == nil {
		t.Fatal("reload changed TLS listener mode")
	}
}

func TestConfigurationValidation(t *testing.T) {
	valid := testApplicationConfig([]string{"http://upstream.internal"})
	tests := map[string]func(*applicationConfig){
		"schema": func(value *applicationConfig) { value.Gateway.SchemaVersion = 9 },
		"duplicate route": func(value *applicationConfig) {
			value.Gateway.Routes = append(value.Gateway.Routes, value.Gateway.Routes[0])
			value.Gateway.Routes[1].Name = "other"
		},
		"authenticated shared cache": func(value *applicationConfig) {
			value.Gateway.CachePolicies = map[string]cachePolicy{"shared": {TTL: duration(60e9), MaxBodyBytes: 1024}}
			value.Gateway.Routes[0].CachePolicy = "shared"
		},
		"wildcard production CORS": func(value *applicationConfig) {
			value.Environment = "production"
			value.Gateway.CORSAllowedOrigins = []string{"*"}
		},
		"upstream credentials": func(value *applicationConfig) {
			value.Gateway.Routes[0].Upstreams = []string{"http://user:password@internal"}
		},
		"dynamic DNS placeholder": func(value *applicationConfig) {
			value.Gateway.DynamicDNS = dynamicDNSConfig{Enabled: true, CheckURL: "https://api.ipify.org", UpdateURL: "https://ddns.example.test/update", Interval: duration(time.Minute), Timeout: duration(time.Second)}
		},
		"admin Prometheus URL": func(value *applicationConfig) {
			value.RedisURL = "redis://redis.internal:6379/0"
			value.Admin.Enabled = true
			value.Admin.PrometheusURL = "file:///tmp/prometheus"
		},
	}
	for name, breakConfig := range tests {
		t.Run(name, func(t *testing.T) {
			configuration := valid
			configuration.Gateway.Routes = append([]routeConfig(nil), valid.Gateway.Routes...)
			breakConfig(&configuration)
			if err := configuration.Validate(); err == nil {
				t.Fatal("Validate succeeded")
			}
		})
	}
}

func TestConfigurationFilesAndEnvironment(t *testing.T) {
	for _, path := range []string{"../../config.example.json", "../../deploy/compose/gateway.json", "../../deploy/compose/control.json"} {
		configuration := defaultConfig()
		if err := vialconfig.Load(&configuration, vialconfig.OptionalFile(path)); err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		if err := configuration.Validate(); err != nil {
			t.Fatalf("validate %s: %v", path, err)
		}
	}
	configuration := testApplicationConfig([]string{"http://upstream.internal"})
	if err := vialconfig.Load(&configuration, vialconfig.Environ([]string{
		"VIAL_REDIS_URL=redis://redis.internal:6379/1",
		"VIAL_ADMIN_ENABLED=true",
		"VIAL_ADMIN_BOOTSTRAP_KEY_SHA256=" + sha256Text("admin-secret"),
		"VIAL_ADMIN_EXTERNAL_URL=http://admin.example.test",
		"VIAL_ADMIN_PROMETHEUS_URL=http://prometheus.internal:9090",
	})); err != nil {
		t.Fatal(err)
	}
	if configuration.RedisURL != "redis://redis.internal:6379/1" || !configuration.Admin.Enabled || configuration.Admin.ExternalURL != "http://admin.example.test" || configuration.Admin.PrometheusURL != "http://prometheus.internal:9090" {
		t.Fatalf("nested environment overrides were not applied: %+v", configuration.Admin)
	}
}

func testApplicationConfig(upstreams []string) applicationConfig {
	configuration := defaultConfig()
	configuration.Environment = "test"
	configuration.Gateway = GatewayConfig{
		SchemaVersion:      gatewaySchemaVersion,
		Version:            1,
		MaxHeaderBytes:     1 << 20,
		CORSAllowedOrigins: []string{"https://client.example"},
		AuthPolicies:       map[string]authPolicy{"clients": {Type: "api_key", Keys: []staticAPIKey{{Name: "test", SHA256: sha256Text("test-api-key-1234"), Scopes: []string{"users.read"}}}}},
		RatePolicies:       map[string]ratePolicy{"default": {Requests: 100, Burst: 10, Window: duration(60e9)}},
		Routes: []routeConfig{{
			Name: "users", Methods: []string{http.MethodGet, http.MethodPost}, PathPrefix: "/api", PathRewrite: "/",
			Upstreams: upstreams, Timeout: duration(2e9), MaxBodyBytes: 1 << 16, AuthPolicy: "clients", Scopes: []string{"users.read"},
			RequestTransform: transformConfig{JSON: jsonTransform{Add: map[string]any{"tenant": "gateway"}, Remove: []string{"remove"}}},
			CircuitBreaker:   circuitBreakerConfig{Failures: 3, OpenFor: duration(1e9)},
		}},
	}
	return configuration
}

func newTestUpstream(t *testing.T, name string, failFirst bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := hits.Add(1)
		if failFirst && current == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body := map[string]any{}
		if request.Body != nil {
			_ = json.NewDecoder(request.Body).Decode(&body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(upstreamRequest{Method: request.Method, Path: request.URL.Path, Body: body, RequestID: request.Header.Get("X-Request-ID"), ForwardedFor: request.Header.Get("X-Forwarded-For"), ForwardedHost: request.Header.Get("X-Forwarded-Host")})
	}))
	t.Cleanup(server.Close)
	_ = name
	return server, &hits
}

func readText(reader io.Reader) string { data, _ := io.ReadAll(reader); return string(data) }
