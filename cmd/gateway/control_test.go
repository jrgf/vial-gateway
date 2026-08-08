package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisControlPlaneAndCache(t *testing.T) {
	redisServer := miniredis.RunT(t)
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	configuration := testApplicationConfig([]string{upstream.URL})
	configuration.RedisURL = "redis://" + redisServer.Addr()
	configuration.Admin.Enabled = true
	configuration.Admin.BootstrapKeySHA = sha256Text("test-admin-key-1234")
	configuration.Gateway.CachePolicies = map[string]cachePolicy{"private": {TTL: duration(time.Minute), MaxBodyBytes: 1 << 16, PerPrincipal: true}}
	configuration.Gateway.Routes[0].CachePolicy = "private"
	app, err := newApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.Start(ctx)
	defer func() { _ = app.Close() }()
	server := httptest.NewServer(app)
	defer server.Close()

	do := func(method, path string, body any, headers map[string]string) *http.Response {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		request, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(encoded))
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	admin := map[string]string{apiKeyHeader: "test-admin-key-1234"}

	t.Run("control-only replica converges at same bootstrap version", func(t *testing.T) {
		controlConfiguration := defaultConfig()
		controlConfiguration.Environment = "test"
		controlConfiguration.RedisURL = "redis://" + redisServer.Addr()
		controlConfiguration.ControlOnly = true
		controlConfiguration.Gateway = GatewayConfig{SchemaVersion: gatewaySchemaVersion, Version: 1}
		controlApp, err := newApp(controlConfiguration)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = controlApp.Close() }()
		controlApp.Start(ctx)
		deadline := time.Now().Add(time.Second)
		for len(controlApp.manager.current.Load().config.Routes) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if len(controlApp.manager.current.Load().config.Routes) != 1 {
			t.Fatal("control replica did not load the active gateway routes")
		}
	})

	t.Run("cache hit and invalidation", func(t *testing.T) {
		for range 2 {
			response := do(http.MethodGet, "/api/cache", nil, map[string]string{apiKeyHeader: "test-api-key-1234"})
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", response.StatusCode)
			}
		}
		if upstreamHits.Load() != 1 {
			t.Fatalf("upstream hits = %d, want 1", upstreamHits.Load())
		}
		response := do(http.MethodPost, "/admin/v1/cache/invalidate", cacheInvalidationRequest{Route: "users"}, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("invalidate status = %d", response.StatusCode)
		}
		response = do(http.MethodGet, "/api/cache", nil, map[string]string{apiKeyHeader: "test-api-key-1234"})
		_ = response.Body.Close()
		if upstreamHits.Load() != 2 {
			t.Fatalf("upstream hits after invalidation = %d", upstreamHits.Load())
		}
	})

	t.Run("immutable config activation and optimistic check", func(t *testing.T) {
		replacement := configuration.Gateway
		replacement.Version = 2
		replacement.Routes[0].PathPrefix = "/v2"
		response := do(http.MethodPost, "/admin/v1/configs/validate", replacement, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("validate status = %d", response.StatusCode)
		}
		response = do(http.MethodPost, "/admin/v1/configs", replacement, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d", response.StatusCode)
		}
		response = do(http.MethodPost, "/admin/v1/configs", replacement, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			t.Fatalf("duplicate status = %d", response.StatusCode)
		}
		activationHeaders := map[string]string{apiKeyHeader: "test-admin-key-1234", "If-Match": "1"}
		response = do(http.MethodPost, "/admin/v1/configs/2/activate", nil, activationHeaders)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || app.manager.current.Load().config.Version != 2 {
			t.Fatalf("activation status=%d version=%d", response.StatusCode, app.manager.current.Load().config.Version)
		}
		response = do(http.MethodPost, "/admin/v1/configs/1/rollback", nil, activationHeaders)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			t.Fatalf("stale activation status = %d", response.StatusCode)
		}
		response = do(http.MethodDelete, "/admin/v1/configs/2", nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusConflict {
			t.Fatalf("active deletion status = %d", response.StatusCode)
		}
		response = do(http.MethodDelete, "/admin/v1/configs/1", nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("inactive deletion status = %d", response.StatusCode)
		}
		response = do(http.MethodGet, "/admin/v1/configs/1", nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("deleted config status = %d", response.StatusCode)
		}
	})

	t.Run("rotatable scoped API key", func(t *testing.T) {
		response := do(http.MethodPost, "/admin/v1/api-keys", createAPIKeyRequest{Name: "client", Scopes: []string{"users.read"}}, admin)
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("create key status = %d", response.StatusCode)
		}
		var created struct {
			ID     string `json:"id"`
			APIKey string `json:"api_key"`
		}
		if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		response = do(http.MethodGet, "/v2/key", nil, map[string]string{apiKeyHeader: created.APIKey})
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("generated key status = %d", response.StatusCode)
		}
		response = do(http.MethodDelete, "/admin/v1/api-keys/"+created.ID, nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("revoke status = %d", response.StatusCode)
		}
		response = do(http.MethodGet, "/v2/key", nil, map[string]string{apiKeyHeader: created.APIKey})
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked key status = %d", response.StatusCode)
		}
	})

	t.Run("session CSRF", func(t *testing.T) {
		session, _ := json.Marshal(adminSession{Subject: "admin@example.test", Scopes: []string{"gateway.admin"}, CSRF: "csrf-token"})
		if err := redisServer.Set(sessionKeyPrefix+"session-id", string(session)); err != nil {
			t.Fatal(err)
		}
		headers := map[string]string{"Cookie": adminCookie + "=session-id"}
		response := do(http.MethodPost, "/admin/v1/configs/validate", configuration.Gateway, headers)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("missing CSRF status = %d", response.StatusCode)
		}
		headers["X-CSRF-Token"] = "csrf-token"
		response = do(http.MethodPost, "/admin/v1/configs/validate", configuration.Gateway, headers)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("valid CSRF status = %d", response.StatusCode)
		}
	})

	t.Run("admin UI read model", func(t *testing.T) {
		response := do(http.MethodGet, "/admin", nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Security-Policy") == "" {
			t.Fatalf("dashboard status=%d csp=%q", response.StatusCode, response.Header.Get("Content-Security-Policy"))
		}
		response = do(http.MethodGet, "/admin/assets/app.css", nil, nil)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/css; charset=utf-8" {
			t.Fatalf("stylesheet status=%d type=%q", response.StatusCode, response.Header.Get("Content-Type"))
		}
		response = do(http.MethodGet, "/admin/v1/status", nil, admin)
		var status struct {
			ActiveVersion int64              `json:"active_version"`
			Routes        []adminRouteStatus `json:"routes"`
		}
		if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || status.ActiveVersion != 2 || len(status.Routes) != 1 || len(status.Routes[0].Upstreams) != 1 {
			t.Fatalf("status=%d version=%d routes=%d", response.StatusCode, status.ActiveVersion, len(status.Routes))
		}
		response = do(http.MethodGet, "/admin/v1/configs/2", nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("config detail status = %d", response.StatusCode)
		}
		response = do(http.MethodGet, "/admin/v1/api-keys", nil, admin)
		var keys struct {
			APIKeys []adminAPIKey `json:"api_keys"`
		}
		if err := json.NewDecoder(response.Body).Decode(&keys); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || len(keys.APIKeys) != 1 || !keys.APIKeys[0].Revoked {
			t.Fatalf("keys status=%d keys=%+v", response.StatusCode, keys.APIKeys)
		}
		response = do(http.MethodGet, "/admin/v1/audit?limit=2", nil, admin)
		var firstAuditPage struct {
			Events     []adminAuditEntry `json:"events"`
			NextCursor string            `json:"next_cursor"`
		}
		if err := json.NewDecoder(response.Body).Decode(&firstAuditPage); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || len(firstAuditPage.Events) != 2 || firstAuditPage.NextCursor == "" {
			t.Fatalf("audit status=%d events=%d cursor=%q", response.StatusCode, len(firstAuditPage.Events), firstAuditPage.NextCursor)
		}
		response = do(http.MethodGet, "/admin/v1/audit?limit=2&before="+firstAuditPage.NextCursor, nil, admin)
		var secondAuditPage struct {
			Events []adminAuditEntry `json:"events"`
		}
		if err := json.NewDecoder(response.Body).Decode(&secondAuditPage); err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || len(secondAuditPage.Events) == 0 || firstAuditPage.Events[1].ID == secondAuditPage.Events[0].ID {
			t.Fatalf("second audit page status=%d events=%+v", response.StatusCode, secondAuditPage.Events)
		}
		response = do(http.MethodGet, "/admin/v1/audit?before=invalid", nil, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid audit cursor status = %d", response.StatusCode)
		}
		empty := configuration.Gateway
		empty.Version = 3
		empty.Routes = nil
		response = do(http.MethodPost, "/admin/v1/configs/validate", empty, admin)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("empty gateway validation status = %d", response.StatusCode)
		}
	})

	if length, err := app.redis.XLen(context.Background(), auditKey).Result(); err != nil || length < 3 {
		t.Fatalf("audit length=%s err=%v", strconv.FormatInt(length, 10), err)
	}
}

func TestStatisticsEndpoint(t *testing.T) {
	prometheus := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		result := `[{"metric":{},"value":[0,"12.5"]}]`
		if strings.Contains(request.URL.Query().Get("query"), "sum by (route)") {
			result = `[{"metric":{"route":"users"},"value":[0,"2.5"]},{"metric":{"route":"orders"},"value":[0,"1"]}]`
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"success","data":{"result":` + result + `}}`))
	}))
	defer prometheus.Close()

	control := &controlPlane{config: adminConfig{PrometheusURL: prometheus.URL}, metricsClient: prometheus.Client()}
	recorder := httptest.NewRecorder()
	control.statistics(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/statistics", nil), adminIdentity{})
	var result struct {
		RequestsPerSecond float64               `json:"requests_per_second"`
		Routes            []adminRouteStatistic `json:"routes"`
	}
	if err := json.NewDecoder(recorder.Result().Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || result.RequestsPerSecond != 12.5 || len(result.Routes) != 2 || result.Routes[0].Route != "users" {
		t.Fatalf("statistics status=%d result=%+v", recorder.Code, result)
	}

	control.config.PrometheusURL = ""
	recorder = httptest.NewRecorder()
	control.statistics(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/statistics", nil), adminIdentity{})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured statistics status = %d", recorder.Code)
	}
}

func TestRateLimitFailsOpenDuringRedisLoss(t *testing.T) {
	redisServer := miniredis.RunT(t)
	upstream, _ := newTestUpstream(t, "users", false)
	configuration := testApplicationConfig([]string{upstream.URL})
	configuration.RedisURL = "redis://" + redisServer.Addr()
	configuration.Gateway.Routes[0].RatePolicy = "default"
	app, err := newApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	server := httptest.NewServer(app)
	defer server.Close()
	redisServer.Close()

	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/outage", nil)
	request.Header.Set(apiKeyHeader, "test-api-key-1234")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want fail-open request to succeed", response.StatusCode)
	}
}

func TestDistributedTokenBucket(t *testing.T) {
	redisServer := miniredis.RunT(t)
	upstream, _ := newTestUpstream(t, "users", false)
	configuration := testApplicationConfig([]string{upstream.URL})
	configuration.RedisURL = "redis://" + redisServer.Addr()
	configuration.Gateway.RatePolicies["default"] = ratePolicy{Requests: 1, Window: duration(time.Minute)}
	configuration.Gateway.Routes[0].RatePolicy = "default"
	app, err := newApp(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	server := httptest.NewServer(app)
	defer server.Close()

	for attempt, expected := range []int{http.StatusOK, http.StatusTooManyRequests} {
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/rate", nil)
		request.Header.Set(apiKeyHeader, "test-api-key-1234")
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("attempt %d status = %d, want %d", attempt+1, response.StatusCode, expected)
		}
	}
}

func TestOIDCLoginRedirectsToCanonicalHost(t *testing.T) {
	control := &controlPlane{config: adminConfig{ExternalURL: "http://127.0.0.1:8081", OIDCIssuer: "http://issuer.example"}}
	request := httptest.NewRequest(http.MethodGet, "http://localhost:8081/admin/login", nil)
	recorder := httptest.NewRecorder()
	control.login(recorder, request)
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != "http://127.0.0.1:8081/admin/login" {
		t.Fatalf("status=%d location=%q", recorder.Code, recorder.Header().Get("Location"))
	}
}
