package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type adminEndpointStatus struct {
	URL     string `json:"url"`
	Healthy bool   `json:"healthy"`
	Breaker string `json:"breaker"`
}

type adminRouteStatus struct {
	Name        string                `json:"name"`
	Hosts       []string              `json:"hosts"`
	Methods     []string              `json:"methods"`
	PathPrefix  string                `json:"path_prefix"`
	AuthPolicy  string                `json:"auth_policy,omitempty"`
	RatePolicy  string                `json:"rate_policy,omitempty"`
	CachePolicy string                `json:"cache_policy,omitempty"`
	Concurrency int                   `json:"concurrency,omitempty"`
	Retries     int                   `json:"retries,omitempty"`
	Streaming   bool                  `json:"streaming,omitempty"`
	Upstreams   []adminEndpointStatus `json:"upstreams"`
	Healthy     int                   `json:"healthy_upstreams"`
}

type adminAPIKey struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	CreatedAt string   `json:"created_at"`
	RevokedAt string   `json:"revoked_at,omitempty"`
	Revoked   bool     `json:"revoked"`
}

type adminAuditEntry struct {
	ID     string `json:"id"`
	At     string `json:"at"`
	Actor  string `json:"actor"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
}

type adminRouteStatistic struct {
	Route             string  `json:"route"`
	RequestsPerSecond float64 `json:"requests_per_second"`
}

type prometheusSample struct {
	Metric map[string]string
	Value  float64
}

type prometheusQueryResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Value  []json.RawMessage `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

//go:embed admin-ui/index.html
var adminHTML string

//go:embed admin-ui/app.css
var adminStyles string

//go:embed admin-ui/app.js
var adminScript string

var adminTemplate = template.Must(template.New("admin").Funcs(template.FuncMap{
	"join": func(values []string) string { return strings.Join(values, ", ") },
	"initial": func(value string) string {
		letters := []rune(value)
		if len(letters) == 0 {
			return "A"
		}
		return strings.ToUpper(string(letters[0]))
	},
}).Parse(adminHTML))

func (control *controlPlane) dashboard(writer http.ResponseWriter, _ *http.Request, identity adminIdentity) {
	snapshot := control.manager.current.Load()
	data := struct {
		Subject, CSRF string
		Version       int64
		Routes        []routeConfig
	}{Subject: identity.Subject, CSRF: identity.CSRF}
	if snapshot != nil {
		data.Version, data.Routes = snapshot.config.Version, snapshot.config.Routes
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Frame-Options", "DENY")
	_ = adminTemplate.Execute(writer, data)
}

func (control *controlPlane) adminCSS(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write([]byte(adminStyles))
}

func (control *controlPlane) adminJS(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write([]byte(adminScript))
}

func (control *controlPlane) status(writer http.ResponseWriter, _ *http.Request, _ adminIdentity) {
	snapshot := control.manager.current.Load()
	if snapshot == nil {
		writeFault(writer, http.StatusServiceUnavailable, "config_unavailable", "No active configuration is loaded")
		return
	}
	routes := make([]adminRouteStatus, 0, len(snapshot.config.Routes))
	healthy, total := 0, 0
	for index, route := range snapshot.config.Routes {
		state := adminRouteStatus{Name: route.Name, Hosts: route.Hosts, Methods: route.Methods, PathPrefix: route.PathPrefix, AuthPolicy: route.AuthPolicy, RatePolicy: route.RatePolicy, CachePolicy: route.CachePolicy, Concurrency: route.Concurrency, Retries: route.Retries, Streaming: route.Streaming}
		if index < len(snapshot.pools) {
			for _, endpoint := range snapshot.pools[index].endpoints {
				upstream := adminEndpointStatus{URL: endpoint.url.String(), Healthy: endpoint.healthy.Load(), Breaker: endpoint.breaker.State().String()}
				state.Upstreams = append(state.Upstreams, upstream)
				total++
				if upstream.Healthy {
					state.Healthy++
					healthy++
				}
			}
		}
		routes = append(routes, state)
	}
	configuration := snapshot.config
	writeJSON(writer, http.StatusOK, map[string]any{
		"active_version": configuration.Version, "schema_version": configuration.SchemaVersion,
		"route_count": len(routes), "healthy_upstreams": healthy, "total_upstreams": total,
		"auth_policy_count": len(configuration.AuthPolicies), "rate_policy_count": len(configuration.RatePolicies), "cache_policy_count": len(configuration.CachePolicies),
		"service_name": configuration.Telemetry.ServiceName, "tracing_enabled": configuration.Telemetry.OTLPEndpoint != "",
		"dynamic_dns_enabled": configuration.DynamicDNS.Enabled, "dynamic_dns_bearer_configured": control.manager.dynamicDNSBearer != "", "routes": routes,
	})
}

func (control *controlPlane) statistics(writer http.ResponseWriter, request *http.Request, _ adminIdentity) {
	if control.config.PrometheusURL == "" {
		writeFault(writer, http.StatusServiceUnavailable, "statistics_unavailable", "Prometheus is not configured")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()
	queries := []struct {
		name       string
		expression string
	}{
		{"requests_per_second", `sum(rate(vial_gateway_requests_total[5m]))`},
		{"error_rate_percent", `100 * sum(rate(vial_gateway_requests_total{status=~"5.."}[5m])) / clamp_min(sum(rate(vial_gateway_requests_total[5m])), 0.000001)`},
		{"upstream_failures_per_second", `sum(rate(vial_gateway_upstream_attempts_total{result!="ok"}[5m]))`},
		{"cache_hit_rate_percent", `100 * sum(rate(vial_gateway_cache_total{result="hit"}[5m])) / clamp_min(sum(rate(vial_gateway_cache_total{result=~"hit|miss"}[5m])), 0.000001)`},
	}
	values := make(map[string]float64, len(queries))
	for _, query := range queries {
		samples, err := control.queryPrometheus(ctx, query.expression)
		if err != nil {
			writeFault(writer, http.StatusServiceUnavailable, "statistics_unavailable", "Prometheus is unavailable")
			return
		}
		if len(samples) > 0 {
			values[query.name] = samples[0].Value
		}
	}
	routeSamples, err := control.queryPrometheus(ctx, `sum by (route) (rate(vial_gateway_requests_total[5m]))`)
	if err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "statistics_unavailable", "Prometheus is unavailable")
		return
	}
	routes := make([]adminRouteStatistic, 0, len(routeSamples))
	for _, sample := range routeSamples {
		if route := sample.Metric["route"]; route != "" {
			routes = append(routes, adminRouteStatistic{Route: route, RequestsPerSecond: sample.Value})
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].RequestsPerSecond > routes[j].RequestsPerSecond })
	writeJSON(writer, http.StatusOK, map[string]any{
		"window": "5m", "requests_per_second": values["requests_per_second"], "error_rate_percent": values["error_rate_percent"],
		"upstream_failures_per_second": values["upstream_failures_per_second"], "cache_hit_rate_percent": values["cache_hit_rate_percent"], "routes": routes,
	})
}

func (control *controlPlane) queryPrometheus(ctx context.Context, expression string) ([]prometheusSample, error) {
	endpoint, err := url.Parse(strings.TrimSuffix(control.config.PrometheusURL, "/") + "/api/v1/query")
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("query", expression)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	client := control.metricsClient
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus returned %s", response.Status)
	}
	var payload prometheusQueryResponse
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Status != "success" {
		return nil, fmt.Errorf("prometheus query failed: %s", payload.Error)
	}
	samples := make([]prometheusSample, 0, len(payload.Data.Result))
	for _, result := range payload.Data.Result {
		if len(result.Value) != 2 {
			continue
		}
		var encoded string
		if json.Unmarshal(result.Value[1], &encoded) != nil {
			continue
		}
		value, err := strconv.ParseFloat(encoded, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			value = 0
		}
		samples = append(samples, prometheusSample{Metric: result.Metric, Value: value})
	}
	return samples, nil
}

func (control *controlPlane) getConfig(writer http.ResponseWriter, request *http.Request, _ adminIdentity) {
	version, err := strconv.ParseInt(request.PathValue("version"), 10, 64)
	if err != nil || version < 1 {
		writeFault(writer, http.StatusBadRequest, "invalid_version", "A positive version is required")
		return
	}
	data, err := control.redis.Get(request.Context(), configKey(version)).Bytes()
	if err == nil {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = writer.Write(data)
		return
	}
	if err == redis.Nil {
		writeFault(writer, http.StatusNotFound, "version_not_found", "Configuration version does not exist")
		return
	}
	writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
}

func (control *controlPlane) listAPIKeys(writer http.ResponseWriter, request *http.Request, _ adminIdentity) {
	keys := []adminAPIKey{}
	var cursor uint64
	for len(keys) < 200 {
		names, next, err := control.redis.Scan(request.Context(), cursor, "vial-gateway:apikey:*", 100).Result()
		if err != nil {
			writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
			return
		}
		for _, name := range names {
			record, err := control.redis.HGetAll(request.Context(), name).Result()
			if err != nil || record["name"] == "" {
				continue
			}
			keys = append(keys, adminAPIKey{ID: strings.TrimPrefix(name, "vial-gateway:apikey:"), Name: record["name"], Scopes: splitSpace(record["scopes"]), CreatedAt: record["created_at"], RevokedAt: record["revoked_at"], Revoked: record["revoked"] == "1"})
			if len(keys) == 200 {
				break
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].CreatedAt > keys[j].CreatedAt })
	writeJSON(writer, http.StatusOK, map[string]any{"api_keys": keys})
}

func (control *controlPlane) listAudit(writer http.ResponseWriter, request *http.Request, _ adminIdentity) {
	limit, _ := strconv.ParseInt(request.URL.Query().Get("limit"), 10, 64)
	if limit < 1 || limit > 200 {
		limit = 25
	}
	start := "+"
	if before := request.URL.Query().Get("before"); before != "" {
		parts := strings.Split(before, "-")
		if len(parts) != 2 {
			writeFault(writer, http.StatusBadRequest, "invalid_cursor", "Audit cursor is invalid")
			return
		}
		if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil {
			writeFault(writer, http.StatusBadRequest, "invalid_cursor", "Audit cursor is invalid")
			return
		}
		if _, err := strconv.ParseUint(parts[1], 10, 64); err != nil {
			writeFault(writer, http.StatusBadRequest, "invalid_cursor", "Audit cursor is invalid")
			return
		}
		start = "(" + before
	}
	messages, err := control.redis.XRevRangeN(request.Context(), auditKey, start, "-", limit+1).Result()
	if err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	hasMore := int64(len(messages)) > limit
	if hasMore {
		messages = messages[:limit]
	}
	entries := make([]adminAuditEntry, 0, len(messages))
	for _, message := range messages {
		value := func(name string) string { return fmt.Sprint(message.Values[name]) }
		entries = append(entries, adminAuditEntry{ID: message.ID, At: value("at"), Actor: value("actor"), Action: value("action"), Target: value("target")})
	}
	nextCursor := ""
	if hasMore && len(entries) > 0 {
		nextCursor = entries[len(entries)-1].ID
	}
	writeJSON(writer, http.StatusOK, map[string]any{"events": entries, "next_cursor": nextCursor})
}
