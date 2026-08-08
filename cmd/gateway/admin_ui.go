package main

import (
	"context"
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

var adminTemplate = template.Must(template.New("admin").Funcs(template.FuncMap{
	"join": func(values []string) string { return strings.Join(values, ", ") },
	"initial": func(value string) string {
		letters := []rune(value)
		if len(letters) == 0 {
			return "A"
		}
		return strings.ToUpper(string(letters[0]))
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Gateway Console · Vial</title>
  <link rel="stylesheet" href="/admin/assets/app.css">
  <script src="/admin/assets/app.js" defer></script>
</head>
<body data-csrf="{{.CSRF}}">
  <a class="skip-link" href="#content">Skip to content</a>
  <aside class="sidebar">
    <a class="brand" href="#statistics" aria-label="Vial Gateway home"><span class="brand-mark">V</span><span><strong>Vial</strong><small>Gateway console</small></span></a>
    <nav aria-label="Gateway management">
      <a href="#statistics" class="nav-link active">Statistics</a>
      <a href="#routes" class="nav-link">Routes</a>
      <a href="#configurations" class="nav-link">Configurations</a>
      <a href="#access" class="nav-link">API keys</a>
      <a href="#dynamic-dns" class="nav-link">Dynamic DNS</a>
      <a href="#cache" class="nav-link">Cache</a>
      <a href="#audit" class="nav-link">Audit log</a>
    </nav>
    <div class="sidebar-foot">
      <div class="identity"><span class="avatar" aria-hidden="true">{{initial .Subject}}</span><span><strong>{{.Subject}}</strong><small>Gateway administrator</small></span></div>
      <form action="/admin/logout" method="post"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="button ghost wide" type="submit">Sign out</button></form>
    </div>
  </aside>

  <main id="content">
    <header class="topbar">
      <div><p class="eyebrow">Control plane</p><h1>Gateway statistics</h1></div>
      <div class="top-actions"><span id="connection" class="status waiting"><i></i>Connecting</span><button id="refresh" class="button secondary" type="button">Refresh</button></div>
    </header>

    <div id="notice" class="notice" role="status" aria-live="polite" hidden></div>

    <section id="statistics" class="section" aria-labelledby="statistics-title">
      <div class="section-head"><div><p class="eyebrow">Traffic and health</p><h2 id="statistics-title">Live gateway statistics</h2></div><span id="last-updated" class="muted">Waiting for data</span></div>
      <div class="stats">
        <article class="stat"><span>Active version</span><strong id="stat-version">{{.Version}}</strong><small>Immutable configuration</small></article>
        <article class="stat"><span>Routes</span><strong id="stat-routes">{{len .Routes}}</strong><small id="stat-policies">Policy inventory</small></article>
        <article class="stat"><span>Upstreams healthy</span><strong id="stat-health">—</strong><small id="health-summary">Health checks loading</small></article>
        <article class="stat"><span>Dynamic DNS</span><strong id="stat-dns">—</strong><small id="dns-summary">External IP worker</small></article>
      </div>
      <div class="panel service-panel">
        <div><span class="pulse"></span><div><strong id="service-name">Vial Gateway</strong><small id="telemetry-summary">Telemetry loading</small></div></div>
        <span id="schema-version" class="tag">Schema v1</span>
      </div>
      <div class="stats traffic-stats">
        <article class="stat"><span>Requests / second</span><strong id="metric-rps">—</strong><small>Five-minute average</small></article>
        <article class="stat"><span>Server error rate</span><strong id="metric-errors">—</strong><small>HTTP 5xx responses</small></article>
        <article class="stat"><span>Upstream failures / second</span><strong id="metric-upstream">—</strong><small>Failed upstream attempts</small></article>
        <article class="stat"><span>Cache hit rate</span><strong id="metric-cache">—</strong><small>Hits among cache lookups</small></article>
      </div>
      <div class="panel table-panel metric-panel">
        <div class="panel-head"><div><h3>Traffic by route</h3><p>Requests per second over the last five minutes</p></div><span id="metrics-state" class="status waiting"><i></i>Loading</span></div>
        <div class="table-wrap"><table><thead><tr><th>Route</th><th>Requests / second</th></tr></thead><tbody id="metric-routes"><tr><td colspan="2" class="empty">Loading traffic statistics…</td></tr></tbody></table></div>
      </div>
    </section>

    <section id="routes" class="section" aria-labelledby="routes-title">
      <div class="section-head"><div><p class="eyebrow">Data plane</p><h2 id="routes-title">Routes & upstreams</h2></div><div class="section-actions"><span id="route-count" class="count">{{len .Routes}} routes</span><button id="add-route" class="button primary" type="button">Add route</button></div></div>
      <div class="panel table-panel"><div class="table-wrap"><table>
        <thead><tr><th>Route</th><th>Match & methods</th><th>Policies</th><th>Upstreams</th><th>Status</th><th><span class="sr-only">Actions</span></th></tr></thead>
        <tbody id="routes-body">{{range .Routes}}<tr><td><strong>{{.Name}}</strong></td><td><code>{{join .Methods}}</code><small>{{.PathPrefix}}</small></td><td><span class="tag">{{if .AuthPolicy}}{{.AuthPolicy}}{{else}}public{{end}}</span></td><td>{{len .Upstreams}}</td><td><span class="status waiting"><i></i>Checking</span></td><td></td></tr>{{else}}<tr><td colspan="6" class="empty">No routes are configured.</td></tr>{{end}}</tbody>
      </table></div></div>
    </section>

    <dialog id="route-dialog" aria-labelledby="route-dialog-title">
      <form id="route-form" class="dialog-form">
        <div class="dialog-head"><div><p class="eyebrow">Atomic route update</p><h2 id="route-dialog-title">Add route</h2></div><button id="close-route" class="icon-button" type="button" aria-label="Close route editor">×</button></div>
        <input id="route-original-name" type="hidden">
        <div class="form-grid">
          <label>Name<input id="route-name" maxlength="80" required placeholder="inventory"></label>
          <label>Path prefix<input id="route-path" required placeholder="/api/inventory"></label>
          <label>Hosts <span class="optional">optional · comma separated</span><input id="route-hosts" placeholder="api.example.com"></label>
          <label>Path rewrite <span class="optional">optional</span><input id="route-rewrite" placeholder="/v1"></label>
        </div>
        <label>Upstream URLs <span class="optional">one per line</span><textarea id="route-upstreams" class="small-textarea" required placeholder="http://inventory:9001"></textarea></label>
        <fieldset><legend>Allowed methods</legend><div id="route-methods" class="method-grid">
          <label><input type="checkbox" value="GET">GET</label><label><input type="checkbox" value="POST">POST</label><label><input type="checkbox" value="PUT">PUT</label><label><input type="checkbox" value="PATCH">PATCH</label><label><input type="checkbox" value="DELETE">DELETE</label><label><input type="checkbox" value="HEAD">HEAD</label><label><input type="checkbox" value="OPTIONS">OPTIONS</label>
        </div><label class="custom-methods">Custom methods <span class="optional">comma separated</span><input id="route-custom-methods" placeholder="PURGE"></label></fieldset>
        <details><summary>Traffic policy options</summary><div class="form-grid details-grid">
          <label>Auth policy<input id="route-auth" placeholder="default"></label>
          <label>Required scopes<input id="route-scopes" placeholder="inventory.read"></label>
          <label>Rate policy<input id="route-rate" placeholder="standard"></label>
          <label>Cache policy<input id="route-cache" placeholder="short"></label>
          <label>Health path<input id="route-health" placeholder="/health"></label>
          <label>Timeout<input id="route-timeout" placeholder="15s"></label>
          <label>Max body bytes<input id="route-max-body" type="number" min="0" step="1" placeholder="1048576"></label>
          <label>Concurrency<input id="route-concurrency" type="number" min="0" step="1" placeholder="0"></label>
          <label>Retries<input id="route-retries" type="number" min="0" step="1" placeholder="0"></label>
          <label class="check-label"><input id="route-redirects" type="checkbox">Keep upstream redirects under path prefix</label>
          <label class="check-label"><input id="route-streaming" type="checkbox">Streaming route</label>
        </div></details>
        <div class="dialog-foot"><p>Saving creates and atomically activates a new immutable configuration version.</p><div><button id="cancel-route" class="button ghost" type="button">Cancel</button><button id="save-route" class="button primary" type="submit">Save & activate</button></div></div>
      </form>
    </dialog>

    <section id="configurations" class="section" aria-labelledby="config-title">
      <div class="section-head"><div><p class="eyebrow">Version control</p><h2 id="config-title">Configurations</h2></div><button id="new-config" class="button secondary" type="button">New from active</button></div>
      <div class="config-grid">
        <article class="panel"><div class="panel-head"><div><h3>Version history</h3><p>Immutable snapshots stored in Redis</p></div></div><div id="versions" class="version-list"><p class="empty">Loading versions…</p></div></article>
        <article class="panel editor-panel"><div class="panel-head"><div><h3 id="editor-title">Configuration editor</h3><p>Validate before saving a new version</p></div><span id="editor-state" class="tag">Not loaded</span></div>
          <label class="sr-only" for="config-editor">Gateway configuration JSON</label><textarea id="config-editor" spellcheck="false" aria-describedby="editor-help"></textarea>
          <div class="editor-foot"><small id="editor-help">JSON · schema version 1 · 2 MiB maximum</small><div><button id="format-config" class="button ghost" type="button">Format</button><button id="validate-config" class="button secondary" type="button">Validate</button><button id="save-config" class="button primary" type="button">Save version</button></div></div>
        </article>
      </div>
    </section>

    <section id="access" class="section" aria-labelledby="access-title">
      <div class="section-head"><div><p class="eyebrow">Credentials</p><h2 id="access-title">API keys</h2></div><span class="muted">Secrets appear once</span></div>
      <div id="secret-panel" class="secret-panel" hidden><div><strong>Copy this key now</strong><p>The secret cannot be retrieved after you leave this page.</p></div><code id="new-secret"></code><button id="copy-secret" class="button secondary" type="button">Copy</button><button id="dismiss-secret" class="icon-button" type="button" aria-label="Dismiss secret">×</button></div>
      <div class="access-grid">
        <form id="key-form" class="panel compact-form"><div class="panel-head"><div><h3>Create API key</h3><p>Grant only the scopes this client needs</p></div></div><label>Name<input id="key-name" name="name" autocomplete="off" maxlength="80" required placeholder="billing-service"></label><label>Scopes<input id="key-scopes" name="scopes" autocomplete="off" required placeholder="orders.read, orders.write"><small>Separate scopes with commas or spaces.</small></label><button class="button primary" type="submit">Create key</button></form>
        <article class="panel table-panel"><div class="panel-head"><div><h3>Issued keys</h3><p>Active and revoked credentials</p></div></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Scopes</th><th>Created</th><th>Status</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody id="keys-body"><tr><td colspan="5" class="empty">Loading keys…</td></tr></tbody></table></div></article>
      </div>
    </section>

    <section id="dynamic-dns" class="section" aria-labelledby="ddns-title">
      <div class="section-head"><div><p class="eyebrow">Public connectivity</p><h2 id="ddns-title">Dynamic DNS</h2></div><span id="ddns-state" class="status waiting"><i></i>Loading</span></div>
      <div class="ddns-grid">
        <form id="ddns-form" class="panel">
          <div class="panel-head"><div><h3>External IP synchronization</h3><p>Update your DNS provider whenever the gateway's public IP changes.</p></div><label class="switch"><input id="ddns-enabled" type="checkbox"><span></span><b>Enabled</b></label></div>
          <label>Public IP check URL<input id="ddns-check-url" type="url" placeholder="https://api.ipify.org"></label>
          <label>DNS update URL <span class="optional">must contain {ip}</span><input id="ddns-update-url" inputmode="url" placeholder="https://dns-provider.example/update?address={ip}"></label>
          <div class="form-grid"><label>Check interval<input id="ddns-interval" placeholder="5m"></label><label>Request timeout<input id="ddns-timeout" placeholder="10s"></label></div>
          <div class="editor-foot"><small>Minimum interval: 10s. HTTPS is required in production.</small><button id="save-ddns" class="button primary" type="submit">Save & activate</button></div>
        </form>
        <aside class="panel feature-card">
          <span class="feature-icon" aria-hidden="true">↗</span><div><p class="eyebrow">Secure credential handling</p><h3 id="ddns-token">Bearer token status loading</h3><p>The optional provider token is read from <code>VIAL_DYNAMIC_DNS_BEARER_TOKEN</code>. It is deliberately excluded from configuration versions, Redis, audit targets, and this browser session.</p></div>
          <div class="callout"><strong>What happens after activation?</strong><p>The worker checks immediately, updates only when the canonical IPv4 or IPv6 address changes, and retries failed updates without losing the last successful state.</p></div>
        </aside>
      </div>
    </section>

    <section id="cache" class="section" aria-labelledby="cache-title">
      <div class="section-head"><div><p class="eyebrow">Operations</p><h2 id="cache-title">Cache management</h2></div></div>
      <form id="cache-form" class="panel inline-form"><div><h3>Invalidate cached responses</h3><p>Clear one route or the complete gateway cache.</p></div><label><span>Scope</span><select id="cache-route"><option value="">All routes</option></select></label><button class="button danger" type="submit">Invalidate cache</button></form>
    </section>

    <section id="audit" class="section" aria-labelledby="audit-title">
      <div class="section-head"><div><p class="eyebrow">Accountability</p><h2 id="audit-title">Audit log</h2></div><button id="refresh-audit" class="button secondary" type="button">Refresh log</button></div>
      <div class="panel table-panel"><div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead><tbody id="audit-body"><tr><td colspan="4" class="empty">Loading audit events…</td></tr></tbody></table></div><div class="pagination"><span id="audit-page" class="muted">Page 1</span><div><button id="audit-previous" class="button ghost" type="button" disabled>Previous</button><button id="audit-next" class="button secondary" type="button" disabled>Next</button></div></div></div>
    </section>
    <footer>Vial Gateway control plane <span>·</span> API <code>/admin/v1</code></footer>
  </main>
</body>
</html>`))

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

const adminStyles = `
:root {
  color-scheme: dark;
  --bg: #090d16;
  --sidebar: #0c111d;
  --surface: #111827;
  --surface-2: #172033;
  --line: #253149;
  --line-soft: #1c2639;
  --text: #eef2ff;
  --muted: #8f9bb3;
  --accent: #7c8cff;
  --accent-2: #5de0bb;
  --danger: #ff6b7d;
  --warning: #f4c76b;
  --shadow: 0 18px 55px rgba(0, 0, 0, .26);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-synthesis: none;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 2rem; }
body { margin: 0; min-width: 320px; background: radial-gradient(circle at 75% -20%, rgba(80, 95, 200, .18), transparent 32rem), var(--bg); color: var(--text); font-size: 14px; line-height: 1.5; }
button, input, select, textarea { font: inherit; }
button, a { -webkit-tap-highlight-color: transparent; }
a { color: inherit; }
.skip-link { position: fixed; z-index: 100; top: .75rem; left: .75rem; transform: translateY(-180%); padding: .7rem 1rem; border-radius: .55rem; background: var(--accent); color: #090d16; font-weight: 800; }
.skip-link:focus { transform: none; }
.sidebar { position: fixed; inset: 0 auto 0 0; z-index: 10; display: flex; width: 248px; flex-direction: column; border-right: 1px solid var(--line-soft); background: rgba(12, 17, 29, .94); padding: 1.5rem 1rem; backdrop-filter: blur(18px); }
.brand { display: flex; align-items: center; gap: .8rem; margin: 0 .4rem 2rem; text-decoration: none; }
.brand-mark { display: grid; width: 40px; height: 40px; place-items: center; border: 1px solid rgba(124, 140, 255, .55); border-radius: 12px; background: linear-gradient(145deg, #8795ff, #5869ea); box-shadow: 0 8px 25px rgba(92, 108, 237, .28); color: white; font-size: 18px; font-weight: 900; }
.brand strong, .brand small, .identity strong, .identity small { display: block; }
.brand strong { font-size: 16px; letter-spacing: .02em; }
.brand small, .identity small { color: var(--muted); font-size: 11px; }
nav { display: grid; gap: .25rem; }
.nav-link { display: block; border: 1px solid transparent; border-radius: 9px; padding: .7rem .8rem; color: #aab4c9; text-decoration: none; transition: .15s ease; }
.nav-link:hover, .nav-link:focus-visible, .nav-link.active { border-color: var(--line); background: var(--surface-2); color: white; outline: none; }
.nav-link.active { box-shadow: inset 3px 0 var(--accent); }
.sidebar-foot { margin-top: auto; border-top: 1px solid var(--line-soft); padding: 1rem .35rem 0; }
.identity { display: flex; min-width: 0; align-items: center; gap: .7rem; margin-bottom: .8rem; }
.identity > span:last-child { min-width: 0; }
.identity strong { overflow: hidden; font-size: 12px; text-overflow: ellipsis; white-space: nowrap; }
.avatar { display: grid; flex: 0 0 auto; width: 32px; height: 32px; place-items: center; border-radius: 50%; background: #24314a; color: #bfc7ff; font-weight: 800; }
main { width: calc(100% - 248px); max-width: 1500px; margin-left: 248px; padding: 0 2.25rem 4rem; }
.topbar { position: sticky; z-index: 8; top: 0; display: flex; min-height: 94px; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--line-soft); background: rgba(9, 13, 22, .86); backdrop-filter: blur(18px); }
h1, h2, h3, p { margin-top: 0; }
h1 { margin-bottom: 0; font-size: clamp(1.45rem, 3vw, 2rem); letter-spacing: -.035em; }
h2 { margin-bottom: 0; font-size: 1.25rem; letter-spacing: -.02em; }
h3 { margin-bottom: .2rem; font-size: .95rem; }
.eyebrow { margin-bottom: .18rem; color: var(--accent-2); font-size: 10px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
.muted, small { color: var(--muted); }
.top-actions { display: flex; align-items: center; gap: .7rem; }
.section { margin-top: 2.3rem; }
.section-head, .panel-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; }
.section-head { margin-bottom: 1rem; }
.section-actions { display: flex; align-items: center; gap: .55rem; }
.panel-head { align-items: flex-start; margin-bottom: 1rem; }
.panel-head p { margin: 0; color: var(--muted); font-size: 12px; }
.stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .85rem; }
.stat, .panel { border: 1px solid var(--line-soft); border-radius: 13px; background: linear-gradient(155deg, rgba(23, 32, 51, .87), rgba(15, 22, 35, .94)); box-shadow: var(--shadow); }
.stat { position: relative; overflow: hidden; padding: 1.15rem; }
.stat::after { position: absolute; right: -1.2rem; bottom: -2.5rem; width: 6rem; height: 6rem; border-radius: 50%; background: rgba(124, 140, 255, .07); content: ""; }
.stat > span { display: block; color: #a7b0c4; font-size: 12px; }
.stat strong { display: block; margin: .42rem 0 .2rem; font-size: 1.8rem; letter-spacing: -.04em; }
.stat small { font-size: 11px; }
.panel { padding: 1.1rem; }
.service-panel { display: flex; align-items: center; justify-content: space-between; margin-top: .85rem; }
.service-panel > div { display: flex; align-items: center; gap: .8rem; }
.service-panel strong, .service-panel small { display: block; }
.traffic-stats, .metric-panel { margin-top: .85rem; }
.pulse { width: 10px; height: 10px; border-radius: 50%; background: var(--accent-2); box-shadow: 0 0 0 5px rgba(93, 224, 187, .09); }
.button, .icon-button { border: 1px solid transparent; border-radius: 8px; cursor: pointer; color: var(--text); font-weight: 750; transition: .15s ease; }
.button { min-height: 36px; padding: .48rem .8rem; font-size: 12px; }
.button:hover { filter: brightness(1.12); transform: translateY(-1px); }
.button:active { transform: none; }
.button:disabled { cursor: wait; opacity: .5; transform: none; }
.button.primary { background: var(--accent); color: #090d16; }
.button.secondary { border-color: var(--line); background: var(--surface-2); }
.button.ghost { border-color: var(--line-soft); background: transparent; color: #b4bed1; }
.button.danger { border-color: rgba(255, 107, 125, .35); background: rgba(255, 107, 125, .1); color: #ff9baa; }
.button.wide { width: 100%; }
.icon-button { width: 34px; height: 34px; background: transparent; font-size: 20px; }
.button:focus-visible, .icon-button:focus-visible, input:focus, select:focus, textarea:focus, a:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.status { display: inline-flex; align-items: center; gap: .42rem; width: fit-content; border: 1px solid var(--line); border-radius: 999px; background: rgba(14, 20, 32, .7); padding: .28rem .58rem; color: #c4cde0; font-size: 11px; font-weight: 700; white-space: nowrap; }
.status i { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.status.good i { background: var(--accent-2); box-shadow: 0 0 9px rgba(93, 224, 187, .8); }
.status.bad i { background: var(--danger); box-shadow: 0 0 9px rgba(255, 107, 125, .7); }
.status.warn i { background: var(--warning); }
.tag, .count { display: inline-flex; align-items: center; width: fit-content; border: 1px solid var(--line); border-radius: 6px; background: #111929; padding: .18rem .42rem; color: #aeb9d0; font-size: 10px; font-weight: 750; white-space: nowrap; }
.tag.active { border-color: rgba(93, 224, 187, .3); background: rgba(93, 224, 187, .08); color: var(--accent-2); }
.tag.revoked { border-color: rgba(255, 107, 125, .25); color: #ff95a4; }
.table-panel { padding: 0; overflow: hidden; }
.table-panel > .panel-head { margin: 0; padding: 1rem 1.1rem; border-bottom: 1px solid var(--line-soft); }
.table-wrap { overflow-x: auto; }
.pagination { display: flex; align-items: center; justify-content: space-between; border-top: 1px solid var(--line-soft); padding: .75rem 1rem; }
.pagination > div { display: flex; gap: .5rem; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th { background: rgba(8, 13, 22, .55); color: #78859d; font-size: 9px; letter-spacing: .1em; text-transform: uppercase; }
th, td { padding: .75rem 1rem; border-bottom: 1px solid var(--line-soft); vertical-align: middle; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(124, 140, 255, .025); }
td strong, td small { display: block; }
td small { margin-top: .15rem; font-size: 10px; }
code { border-radius: 5px; background: #0a101b; padding: .15rem .34rem; color: #c7ceff; font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; }
.policy-stack, .endpoint-list { display: flex; flex-wrap: wrap; gap: .3rem; }
.endpoint { display: flex; align-items: center; gap: .4rem; }
.endpoint-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--danger); }
.endpoint-dot.good { background: var(--accent-2); }
.empty { padding: 2rem; color: var(--muted); text-align: center; }
.config-grid { display: grid; grid-template-columns: minmax(260px, .72fr) minmax(400px, 1.8fr); gap: .85rem; }
.version-list { display: grid; gap: .45rem; max-height: 470px; overflow-y: auto; }
.version { display: flex; align-items: center; justify-content: space-between; gap: .75rem; border: 1px solid var(--line-soft); border-radius: 9px; padding: .65rem .7rem; background: rgba(8, 13, 22, .42); }
.version > div:first-child { display: flex; align-items: center; gap: .55rem; }
.version-actions { display: flex; gap: .35rem; }
.version .button { min-height: 30px; padding: .3rem .52rem; }
.editor-panel { min-width: 0; }
textarea { display: block; width: 100%; min-height: 345px; resize: vertical; border: 1px solid var(--line); border-radius: 9px; background: #080d16; padding: .9rem; color: #d7ddf5; font: 12px/1.65 ui-monospace, SFMono-Regular, Menlo, monospace; tab-size: 2; }
.editor-foot { display: flex; align-items: center; justify-content: space-between; gap: .75rem; margin-top: .75rem; }
.editor-foot > div { display: flex; gap: .45rem; }
.access-grid { display: grid; grid-template-columns: minmax(250px, .65fr) minmax(500px, 1.6fr); gap: .85rem; }
.compact-form { display: flex; flex-direction: column; }
label { display: grid; gap: .35rem; margin-bottom: .85rem; color: #b9c2d5; font-size: 11px; font-weight: 750; }
input, select { width: 100%; min-height: 40px; border: 1px solid var(--line); border-radius: 8px; background: #0a101b; padding: .52rem .65rem; color: var(--text); }
input::placeholder { color: #526078; }
label small { font-weight: 400; }
.compact-form > .button { margin-top: auto; }
.ddns-grid { display: grid; grid-template-columns: minmax(420px, 1.25fr) minmax(280px, .75fr); gap: .85rem; }
.switch { display: flex; align-items: center; gap: .5rem; margin: 0; cursor: pointer; }
.switch input { position: absolute; width: 1px; height: 1px; min-height: 0; opacity: 0; }
.switch span { position: relative; width: 38px; height: 21px; border: 1px solid var(--line); border-radius: 999px; background: #0a101b; transition: .15s ease; }
.switch span::after { position: absolute; top: 3px; left: 3px; width: 13px; height: 13px; border-radius: 50%; background: var(--muted); content: ""; transition: .15s ease; }
.switch input:checked + span { border-color: rgba(93, 224, 187, .45); background: rgba(93, 224, 187, .15); }
.switch input:checked + span::after { left: 20px; background: var(--accent-2); }
.switch input:focus-visible + span { outline: 2px solid var(--accent); outline-offset: 2px; }
.switch b { font-size: 11px; }
.feature-card { display: flex; flex-direction: column; gap: .85rem; }
.feature-card > div > p:not(.eyebrow), .callout p { margin: .35rem 0 0; color: var(--muted); font-size: 12px; }
.feature-icon { display: grid; width: 42px; height: 42px; place-items: center; border: 1px solid rgba(124, 140, 255, .35); border-radius: 12px; background: rgba(124, 140, 255, .09); color: #aeb7ff; font-size: 22px; }
.callout { margin-top: auto; border: 1px solid var(--line-soft); border-radius: 9px; background: rgba(8, 13, 22, .42); padding: .8rem; }
.callout strong { font-size: 11px; }
.secret-panel { position: relative; display: grid; grid-template-columns: 1fr minmax(260px, 1.5fr) auto auto; align-items: center; gap: .9rem; margin-bottom: .85rem; border: 1px solid rgba(244, 199, 107, .28); border-radius: 11px; background: rgba(244, 199, 107, .07); padding: .8rem 1rem; }
.secret-panel[hidden] { display: none; }
.secret-panel p { margin: .1rem 0 0; color: #c0ad85; font-size: 11px; }
.secret-panel code { overflow: hidden; padding: .55rem; text-overflow: ellipsis; white-space: nowrap; }
.inline-form { display: grid; grid-template-columns: 1fr minmax(220px, .45fr) auto; align-items: end; gap: 1rem; }
.inline-form h3 { margin-bottom: .15rem; }
.inline-form p { margin: 0; color: var(--muted); font-size: 12px; }
.inline-form label { margin: 0; }
.notice { position: fixed; z-index: 50; right: 1.5rem; bottom: 1.5rem; max-width: min(420px, calc(100vw - 2rem)); border: 1px solid var(--line); border-radius: 10px; background: #182238; padding: .75rem 1rem; box-shadow: var(--shadow); color: white; font-weight: 650; }
.notice.error { border-color: rgba(255, 107, 125, .45); background: #301720; }
dialog { width: min(760px, calc(100vw - 2rem)); max-height: calc(100vh - 2rem); overflow-y: auto; border: 1px solid var(--line); border-radius: 15px; background: var(--surface); padding: 0; color: var(--text); box-shadow: 0 35px 100px rgba(0, 0, 0, .65); }
dialog::backdrop { background: rgba(2, 6, 13, .78); backdrop-filter: blur(5px); }
.dialog-form { padding: 1.25rem; }
.dialog-head, .dialog-foot { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; }
.dialog-head { margin-bottom: 1.15rem; }
.dialog-foot { align-items: center; margin-top: 1rem; border-top: 1px solid var(--line-soft); padding-top: 1rem; }
.dialog-foot p { max-width: 28rem; margin: 0; color: var(--muted); font-size: 11px; }
.dialog-foot > div { display: flex; gap: .5rem; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 .8rem; }
.optional { color: var(--muted); font-size: 9px; font-weight: 500; }
.small-textarea { min-height: 80px; }
fieldset { margin: 0 0 .85rem; border: 1px solid var(--line); border-radius: 9px; padding: .75rem; }
legend { padding: 0 .35rem; color: #b9c2d5; font-size: 11px; font-weight: 750; }
.method-grid { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: .35rem; }
.method-grid label, .check-label { display: flex; align-items: center; gap: .35rem; margin: 0; border: 1px solid var(--line-soft); border-radius: 7px; background: #0a101b; padding: .48rem; cursor: pointer; }
.method-grid input, .check-label input { width: 14px; min-height: 14px; margin: 0; accent-color: var(--accent); }
.custom-methods { margin: .75rem 0 0; }
details { margin-top: .9rem; border: 1px solid var(--line-soft); border-radius: 9px; background: rgba(8, 13, 22, .35); }
summary { cursor: pointer; padding: .7rem .8rem; color: #c5cee0; font-size: 12px; font-weight: 750; }
.details-grid { padding: .2rem .8rem .1rem; }
.details-grid .check-label { align-self: end; min-height: 40px; margin-bottom: .85rem; }
footer { padding-top: 3rem; color: #68748b; font-size: 11px; text-align: center; }
footer span { padding: 0 .4rem; }
.sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); clip-path: inset(50%); white-space: nowrap; }
@media (max-width: 1080px) {
  .stats { grid-template-columns: repeat(2, 1fr); }
  .config-grid, .access-grid, .ddns-grid { grid-template-columns: 1fr; }
}
@media (max-width: 760px) {
  .sidebar { position: sticky; top: 0; width: 100%; height: auto; flex-direction: row; align-items: center; overflow-x: auto; padding: .65rem .75rem; }
  .brand { margin: 0 .8rem 0 0; }
  .brand small, .brand strong, .sidebar-foot { display: none; }
  .brand-mark { width: 34px; height: 34px; }
  nav { display: flex; }
  .nav-link { padding: .5rem .65rem; white-space: nowrap; }
  main { width: 100%; margin-left: 0; padding: 0 1rem 3rem; }
  .topbar { min-height: 76px; }
  .topbar .status { display: none; }
  .secret-panel, .inline-form { grid-template-columns: 1fr; align-items: stretch; }
  .method-grid { grid-template-columns: repeat(4, 1fr); }
}
@media (max-width: 500px) {
  .stats { grid-template-columns: 1fr; }
  .section-head { align-items: flex-start; }
  .editor-foot { align-items: stretch; flex-direction: column; }
  .editor-foot > div { display: grid; grid-template-columns: repeat(3, 1fr); }
  th, td { padding: .65rem .75rem; }
  .form-grid { grid-template-columns: 1fr; }
  .dialog-foot { align-items: stretch; flex-direction: column; }
  .dialog-foot > div { display: grid; grid-template-columns: 1fr 1fr; width: 100%; }
}
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; } }
`

const adminScript = `
(function () {
  'use strict';

  var csrf = document.body.dataset.csrf || '';
  var model = { active: '', routes: [], editorVersion: 0, routeBaseVersion: '', routeDraft: null, ddnsBaseVersion: '', auditCursors: [''], auditPage: 0 };
  var noticeTimer;
  var $ = function (id) { return document.getElementById(id); };

  function make(tag, className, value) {
    var item = document.createElement(tag);
    if (className) item.className = className;
    if (value !== undefined) item.textContent = value;
    return item;
  }

  function show(message, failed) {
    var box = $('notice');
    box.textContent = message;
    box.className = failed ? 'notice error' : 'notice';
    box.hidden = false;
    window.clearTimeout(noticeTimer);
    noticeTimer = window.setTimeout(function () { box.hidden = true; }, failed ? 7000 : 3500);
  }

  async function api(path, options) {
    options = options || {};
    var headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (options.body !== undefined) {
      headers.set('Content-Type', 'application/json');
      if (typeof options.body !== 'string') options.body = JSON.stringify(options.body);
    }
    if (csrf && options.method && options.method !== 'GET') headers.set('X-CSRF-Token', csrf);
    options.headers = headers;
    var response = await fetch(path, options);
    var type = response.headers.get('content-type') || '';
    var data = type.indexOf('application/json') >= 0 ? await response.json() : null;
    if (!response.ok) {
      var message = data && data.error && data.error.message ? data.error.message : 'Request failed (' + response.status + ')';
      throw new Error(message);
    }
    return data;
  }

  function statusPill(good, text, warning) {
    var item = make('span', 'status ' + (warning ? 'warn' : good ? 'good' : 'bad'));
    item.append(make('i'), document.createTextNode(text));
    return item;
  }

  function tag(text, className) { return make('span', 'tag' + (className ? ' ' + className : ''), text); }

  function formatDate(value) {
    if (!value) return '—';
    var date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }

  function setConnection(ok) {
    var item = $('connection');
    item.className = 'status ' + (ok ? 'good' : 'bad');
    item.replaceChildren(make('i'), document.createTextNode(ok ? 'Control plane online' : 'Control plane unavailable'));
  }

  function renderStatus(data) {
    model.active = String(data.active_version);
    model.routes = data.routes || [];
    $('stat-version').textContent = data.active_version;
    $('stat-routes').textContent = data.route_count;
    $('stat-policies').textContent = data.auth_policy_count + ' auth · ' + data.rate_policy_count + ' rate · ' + data.cache_policy_count + ' cache';
    $('stat-health').textContent = data.healthy_upstreams + ' / ' + data.total_upstreams;
    $('health-summary').textContent = data.total_upstreams && data.healthy_upstreams === data.total_upstreams ? 'All endpoints available' : 'Endpoint attention required';
    $('stat-dns').textContent = data.dynamic_dns_enabled ? 'Enabled' : 'Disabled';
    $('dns-summary').textContent = data.dynamic_dns_enabled ? 'External IP changes are monitored' : 'External IP worker is off';
    $('ddns-state').className = 'status ' + (data.dynamic_dns_enabled ? 'good' : 'waiting');
    $('ddns-state').replaceChildren(make('i'), document.createTextNode(data.dynamic_dns_enabled ? 'Worker enabled' : 'Worker disabled'));
    $('ddns-token').textContent = data.dynamic_dns_bearer_configured ? 'Provider bearer token configured' : 'No provider bearer token configured';
    $('service-name').textContent = data.service_name || 'Vial Gateway';
    $('telemetry-summary').textContent = data.tracing_enabled ? 'OTLP trace export enabled' : 'Metrics enabled · tracing disabled';
    $('schema-version').textContent = 'Schema v' + data.schema_version;
    $('route-count').textContent = data.route_count + (data.route_count === 1 ? ' route' : ' routes');
    $('last-updated').textContent = 'Updated ' + new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' }).format(new Date());
    renderRoutes(model.routes);
    renderCacheRoutes(model.routes);
  }

  function formatMetric(value, suffix) {
    var number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return number.toLocaleString(undefined, { minimumFractionDigits: number > 0 && number < 1 ? 2 : 0, maximumFractionDigits: 2 }) + (suffix || '');
  }

  function renderStatistics(data) {
    $('metric-rps').textContent = formatMetric(data.requests_per_second);
    $('metric-errors').textContent = formatMetric(data.error_rate_percent, '%');
    $('metric-upstream').textContent = formatMetric(data.upstream_failures_per_second);
    $('metric-cache').textContent = formatMetric(data.cache_hit_rate_percent, '%');
    $('metrics-state').className = 'status good';
    $('metrics-state').replaceChildren(make('i'), document.createTextNode('Prometheus · ' + data.window));
    var body = $('metric-routes');
    body.replaceChildren();
    if (!data.routes || !data.routes.length) {
      var emptyRow = make('tr');
      var emptyCell = make('td', 'empty', 'No route traffic recorded in this window.');
      emptyCell.colSpan = 2;
      emptyRow.append(emptyCell);
      body.append(emptyRow);
      return;
    }
    data.routes.forEach(function (route) {
      var row = make('tr');
      row.append(make('td', '', route.route), make('td', '', formatMetric(route.requests_per_second)));
      body.append(row);
    });
  }

  async function loadStatistics(quiet) {
    try { renderStatistics(await api('/admin/v1/statistics')); }
    catch (error) {
      ['metric-rps', 'metric-errors', 'metric-upstream', 'metric-cache'].forEach(function (id) { $(id).textContent = '—'; });
      $('metrics-state').className = 'status bad';
      $('metrics-state').replaceChildren(make('i'), document.createTextNode('Unavailable'));
      if (!quiet) show(error.message, true);
    }
  }

  function renderRoutes(routes) {
    var body = $('routes-body');
    body.replaceChildren();
    if (!routes.length) {
      var emptyRow = make('tr');
      var emptyCell = make('td', 'empty', 'No routes are configured. Create a configuration version to add one.');
      emptyCell.colSpan = 6;
      emptyRow.append(emptyCell);
      body.append(emptyRow);
      return;
    }
    routes.forEach(function (route) {
      var row = make('tr');
      var routeCell = make('td');
      routeCell.append(make('strong', '', route.name));
      routeCell.append(make('small', '', route.hosts && route.hosts.length ? route.hosts.join(', ') : 'Any host'));
      var match = make('td');
      match.append(make('code', '', (route.methods || []).join(' · ') || 'ANY'));
      match.append(make('small', '', route.path_prefix));
      var policies = make('td');
      var policyStack = make('div', 'policy-stack');
      if (route.auth_policy) policyStack.append(tag('auth: ' + route.auth_policy));
      if (route.rate_policy) policyStack.append(tag('rate: ' + route.rate_policy));
      if (route.cache_policy) policyStack.append(tag('cache: ' + route.cache_policy));
      if (route.streaming) policyStack.append(tag('streaming'));
      if (!policyStack.childElementCount) policyStack.append(tag('public'));
      policies.append(policyStack);
      var upstreams = make('td');
      var list = make('div', 'endpoint-list');
      var endpoints = route.upstreams || [];
      endpoints.forEach(function (endpoint) {
        var endpointNode = make('span', 'endpoint');
        endpointNode.title = endpoint.url + ' · circuit ' + endpoint.breaker;
        endpointNode.append(make('span', 'endpoint-dot' + (endpoint.healthy ? ' good' : '')));
        endpointNode.append(make('code', '', new URL(endpoint.url).host));
        list.append(endpointNode);
      });
      upstreams.append(list);
      var healthy = endpoints.length > 0 && route.healthy_upstreams === endpoints.length;
      var health = make('td');
      health.append(statusPill(healthy, route.healthy_upstreams + '/' + endpoints.length + ' healthy', route.healthy_upstreams > 0 && !healthy));
      var actions = make('td');
      var actionStack = make('div', 'version-actions');
      actionStack.append(button('Edit', 'ghost', function () { openRoute(route.name); }));
      actionStack.append(button('Remove', 'danger', function () { removeRoute(route.name); }));
      actions.append(actionStack);
      row.append(routeCell, match, policies, upstreams, health, actions);
      body.append(row);
    });
  }

  function renderCacheRoutes(routes) {
    var select = $('cache-route');
    var selected = select.value;
    select.replaceChildren(new Option('All routes', ''));
    routes.forEach(function (route) { select.append(new Option(route.name, route.name)); });
    if (Array.from(select.options).some(function (option) { return option.value === selected; })) select.value = selected;
  }

  async function loadStatus(quiet) {
    try {
      renderStatus(await api('/admin/v1/status'));
      setConnection(true);
      if (!quiet) show('Live gateway status refreshed.');
    } catch (error) {
      setConnection(false);
      if (!quiet) show(error.message, true);
    }
  }

  function button(text, className, action) {
    var item = make('button', 'button ' + className, text);
    item.type = 'button';
    item.addEventListener('click', action);
    return item;
  }

  function renderVersions(data) {
    model.active = String(data.active || model.active);
    var list = $('versions');
    list.replaceChildren();
    if (!data.versions || !data.versions.length) {
      list.append(make('p', 'empty', 'No stored configurations.'));
      return;
    }
    data.versions.forEach(function (version) {
      var current = String(version) === model.active;
      var row = make('div', 'version');
      var title = make('div');
      title.append(make('strong', '', 'Version ' + version));
      if (current) title.append(tag('Active', 'active'));
      var actions = make('div', 'version-actions');
      actions.append(button('View', 'ghost', function () { loadConfig(version); }));
      if (!current) {
        actions.append(button(Number(version) < Number(model.active) ? 'Rollback' : 'Activate', 'secondary', function () { activateConfig(version); }));
        actions.append(button('Delete', 'danger', function () { deleteConfig(version); }));
      }
      row.append(title, actions);
      list.append(row);
    });
  }

  async function loadVersions() {
    try { renderVersions(await api('/admin/v1/configs')); }
    catch (error) { show(error.message, true); }
  }

  async function loadConfig(version) {
    try {
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(version));
      configuration.version = Number(version);
      model.editorVersion = configuration.version;
      $('config-editor').value = JSON.stringify(configuration, null, 2);
      $('editor-title').textContent = 'Configuration version ' + model.editorVersion;
      $('editor-state').textContent = String(model.editorVersion) === model.active ? 'Active' : 'Stored';
      $('editor-state').className = 'tag' + (String(model.editorVersion) === model.active ? ' active' : '');
    } catch (error) { show(error.message, true); }
  }

  function editorJSON() {
    try { return JSON.parse($('config-editor').value); }
    catch (error) { throw new Error('Configuration JSON is invalid: ' + error.message); }
  }

  async function validateConfig() {
    try {
      var result = await api('/admin/v1/configs/validate', { method: 'POST', body: editorJSON() });
      $('editor-state').textContent = 'Valid';
      $('editor-state').className = 'tag active';
      show('Version ' + result.version + ' is valid.');
    } catch (error) {
      $('editor-state').textContent = 'Invalid';
      $('editor-state').className = 'tag revoked';
      show(error.message, true);
    }
  }

  async function saveConfig() {
    try {
      var configuration = editorJSON();
      var result = await api('/admin/v1/configs', { method: 'POST', body: configuration });
      model.editorVersion = Number(result.version);
      show('Configuration version ' + result.version + ' saved. Activate it when ready.');
      await loadVersions();
    } catch (error) { show(error.message, true); }
  }

  async function activateConfig(version) {
    var rollback = Number(version) < Number(model.active);
    if (!window.confirm((rollback ? 'Roll back' : 'Activate') + ' configuration version ' + version + '?')) return;
    try {
      await api('/admin/v1/configs/' + encodeURIComponent(version) + '/' + (rollback ? 'rollback' : 'activate'), { method: 'POST', headers: { 'If-Match': model.active } });
      show('Configuration version ' + version + ' is active.');
      await Promise.all([loadStatus(true), loadVersions(), loadAudit()]);
      await loadConfig(version);
    } catch (error) { show(error.message, true); }
  }

  async function deleteConfig(version) {
    if (!window.confirm('Permanently delete inactive configuration version ' + version + '? This cannot be undone.')) return;
    try {
      await api('/admin/v1/configs/' + encodeURIComponent(version), { method: 'DELETE' });
      show('Configuration version ' + version + ' deleted.');
      await Promise.all([loadVersions(), loadAudit()]);
      if (model.editorVersion === Number(version)) await loadConfig(model.active);
    } catch (error) { show(error.message, true); }
  }

  async function newConfig() {
    try {
      var versions = await api('/admin/v1/configs');
      var active = String(versions.active);
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
      var allVersions = (versions.versions || []).map(Number);
      configuration.version = Math.max(Number(active), allVersions.length ? Math.max.apply(Math, allVersions) : 0) + 1;
      $('config-editor').value = JSON.stringify(configuration, null, 2);
      model.editorVersion = configuration.version;
      $('editor-title').textContent = 'New configuration version ' + configuration.version;
      $('editor-state').textContent = 'Draft';
      $('editor-state').className = 'tag';
      $('config-editor').focus();
    } catch (error) { show(error.message, true); }
  }

  function splitValues(value) {
    return value.split(/[\s,]+/).map(function (item) { return item.trim(); }).filter(Boolean);
  }

  async function openRoute(name) {
    try {
      var versions = await api('/admin/v1/configs');
      var active = String(versions.active);
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
      var route = name ? (configuration.routes || []).find(function (item) { return item.name === name; }) : null;
      if (name && !route) throw new Error('Route no longer exists. Refresh and try again.');
      model.routeBaseVersion = active;
      model.routeDraft = route ? JSON.parse(JSON.stringify(route)) : null;
      $('route-form').reset();
      $('route-original-name').value = route ? route.name : '';
      $('route-name').value = route ? route.name : '';
      $('route-path').value = route ? route.path_prefix : '';
      $('route-hosts').value = route && route.hosts ? route.hosts.join(', ') : '';
      $('route-rewrite').value = route ? route.path_rewrite || '' : '';
      $('route-upstreams').value = route && route.upstreams ? route.upstreams.join('\n') : '';
      var common = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
      var methods = route && route.methods ? route.methods.map(function (method) { return method.toUpperCase(); }) : ['GET'];
      document.querySelectorAll('#route-methods input').forEach(function (input) { input.checked = methods.includes(input.value); });
      $('route-custom-methods').value = methods.filter(function (method) { return !common.includes(method); }).join(', ');
      $('route-auth').value = route ? route.auth_policy || '' : '';
      $('route-scopes').value = route && route.scopes ? route.scopes.join(', ') : '';
      $('route-rate').value = route ? route.rate_policy || '' : '';
      $('route-cache').value = route ? route.cache_policy || '' : '';
      $('route-health').value = route ? route.health_path || '' : '';
      $('route-timeout').value = route ? route.timeout || '' : '15s';
      $('route-max-body').value = route ? route.max_body_bytes || '' : '1048576';
      $('route-concurrency').value = route ? route.concurrency || '' : '';
      $('route-retries').value = route ? route.retries || '' : '';
      $('route-redirects').checked = route ? !!route.rewrite_redirects : false;
      $('route-streaming').checked = route ? !!route.streaming : false;
      $('route-dialog-title').textContent = route ? 'Edit route ' + route.name : 'Add route';
      $('save-route').textContent = route ? 'Save & activate' : 'Add & activate';
      $('route-dialog').showModal();
      $('route-name').focus();
    } catch (error) { show(error.message, true); }
  }

  function readRoute() {
    var route = model.routeDraft ? JSON.parse(JSON.stringify(model.routeDraft)) : {};
    var methods = Array.from(document.querySelectorAll('#route-methods input:checked')).map(function (input) { return input.value; });
    methods = methods.concat(splitValues($('route-custom-methods').value).map(function (method) { return method.toUpperCase(); }));
    methods = Array.from(new Set(methods));
    var upstreams = $('route-upstreams').value.split(/\r?\n/).map(function (item) { return item.trim(); }).filter(Boolean);
    if (!methods.length) throw new Error('Select at least one HTTP method.');
    if (!upstreams.length) throw new Error('Add at least one upstream URL.');
    route.name = $('route-name').value.trim();
    route.hosts = $('route-hosts').value.split(',').map(function (item) { return item.trim(); }).filter(Boolean);
    route.methods = methods;
    route.path_prefix = $('route-path').value.trim();
    route.path_rewrite = $('route-rewrite').value.trim();
    route.upstreams = upstreams;
    route.health_path = $('route-health').value.trim();
    route.health_interval = route.health_interval || '10s';
    route.timeout = $('route-timeout').value.trim() || route.timeout || '15s';
    route.max_body_bytes = Number($('route-max-body').value || route.max_body_bytes || 1048576);
    route.auth_policy = $('route-auth').value.trim();
    route.scopes = splitValues($('route-scopes').value);
    route.rate_policy = $('route-rate').value.trim();
    route.concurrency = Number($('route-concurrency').value || 0);
    route.retries = Number($('route-retries').value || 0);
    route.circuit_breaker = route.circuit_breaker || { failures: 5, open_for: '30s' };
    route.cache_policy = $('route-cache').value.trim();
    route.request_transform = route.request_transform || { set_headers: {}, remove_headers: [], json: { add: {}, remove: [], rename: {} } };
    route.response_transform = route.response_transform || { set_headers: {}, remove_headers: [], json: { add: {}, remove: [], rename: {} } };
    route.rewrite_redirects = $('route-redirects').checked;
    route.streaming = $('route-streaming').checked;
    if (!route.name || !route.path_prefix) throw new Error('Route name and path prefix are required.');
    return route;
  }

  async function deployConfigChange(expectedVersion, change, message) {
    var versions = await api('/admin/v1/configs');
    var active = String(versions.active);
    if (expectedVersion && expectedVersion !== active) throw new Error('The active configuration changed. Reopen the route and try again.');
    var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
    change(configuration);
    var allVersions = (versions.versions || []).map(Number);
    configuration.version = Math.max(Number(active), allVersions.length ? Math.max.apply(Math, allVersions) : 0) + 1;
    await api('/admin/v1/configs/validate', { method: 'POST', body: configuration });
    await api('/admin/v1/configs', { method: 'POST', body: configuration });
    await api('/admin/v1/configs/' + configuration.version + '/activate', { method: 'POST', headers: { 'If-Match': active } });
    show(message + ' Configuration version ' + configuration.version + ' is active.');
    await Promise.all([loadStatus(true), loadVersions(), loadAudit()]);
    await loadConfig(configuration.version);
  }

  async function saveRoute(event) {
    event.preventDefault();
    var save = $('save-route');
    save.disabled = true;
    try {
      var route = readRoute();
      var original = $('route-original-name').value;
      await deployConfigChange(model.routeBaseVersion, function (configuration) {
        configuration.routes = configuration.routes || [];
        if (!original) {
          configuration.routes.push(route);
          return;
        }
        var index = configuration.routes.findIndex(function (item) { return item.name === original; });
        if (index < 0) throw new Error('Route no longer exists.');
        configuration.routes[index] = route;
      }, original ? 'Route updated.' : 'Route added.');
      $('route-dialog').close();
    } catch (error) { show(error.message, true); }
    finally { save.disabled = false; }
  }

  async function removeRoute(name) {
    if (!window.confirm('Remove route "' + name + '" and activate the change?')) return;
    try {
      await deployConfigChange(model.active, function (configuration) {
        configuration.routes = (configuration.routes || []).filter(function (route) { return route.name !== name; });
        if (!configuration.routes.length) throw new Error('The gateway must keep at least one route.');
      }, 'Route "' + name + '" removed.');
    } catch (error) { show(error.message, true); }
  }

  async function loadDynamicDNS() {
    try {
      var versions = await api('/admin/v1/configs');
      var active = String(versions.active);
      var configuration = await api('/admin/v1/configs/' + encodeURIComponent(active));
      var dynamicDNS = configuration.dynamic_dns || {};
      model.ddnsBaseVersion = active;
      $('ddns-enabled').checked = !!dynamicDNS.enabled;
      $('ddns-check-url').value = dynamicDNS.check_url || '';
      $('ddns-update-url').value = dynamicDNS.update_url || '';
      $('ddns-interval').value = dynamicDNS.interval || '5m';
      $('ddns-timeout').value = dynamicDNS.timeout || '10s';
    } catch (error) { show(error.message, true); }
  }

  async function saveDynamicDNS(event) {
    event.preventDefault();
    var save = $('save-ddns');
    save.disabled = true;
    try {
      var dynamicDNS = {
        enabled: $('ddns-enabled').checked,
        check_url: $('ddns-check-url').value.trim(),
        update_url: $('ddns-update-url').value.trim(),
        interval: $('ddns-interval').value.trim() || '5m',
        timeout: $('ddns-timeout').value.trim() || '10s'
      };
      if (dynamicDNS.enabled && (!dynamicDNS.check_url || !dynamicDNS.update_url)) throw new Error('Both Dynamic DNS URLs are required when the worker is enabled.');
      if (dynamicDNS.enabled && dynamicDNS.update_url.indexOf('{ip}') < 0) throw new Error('The DNS update URL must contain the {ip} placeholder.');
      await deployConfigChange(model.ddnsBaseVersion, function (configuration) { configuration.dynamic_dns = dynamicDNS; }, dynamicDNS.enabled ? 'Dynamic DNS enabled.' : 'Dynamic DNS configuration saved.');
      await loadDynamicDNS();
    } catch (error) { show(error.message, true); }
    finally { save.disabled = false; }
  }

  function renderKeys(data) {
    var body = $('keys-body');
    body.replaceChildren();
    if (!data.api_keys || !data.api_keys.length) {
      var row = make('tr');
      var cell = make('td', 'empty', 'No dynamic API keys have been issued.');
      cell.colSpan = 5;
      row.append(cell);
      body.append(row);
      return;
    }
    data.api_keys.forEach(function (key) {
      var row = make('tr');
      var name = make('td');
      name.append(make('strong', '', key.name));
      name.append(make('small', '', key.id.slice(0, 12) + '…'));
      var scopes = make('td');
      var stack = make('div', 'policy-stack');
      (key.scopes || []).forEach(function (scope) { stack.append(tag(scope)); });
      scopes.append(stack);
      var created = make('td', '', formatDate(key.created_at));
      var state = make('td');
      state.append(tag(key.revoked ? 'Revoked' : 'Active', key.revoked ? 'revoked' : 'active'));
      var actions = make('td');
      if (!key.revoked) actions.append(button('Revoke', 'danger', function () { revokeKey(key); }));
      row.append(name, scopes, created, state, actions);
      body.append(row);
    });
  }

  async function loadKeys() {
    try { renderKeys(await api('/admin/v1/api-keys')); }
    catch (error) { show(error.message, true); }
  }

  async function createKey(event) {
    event.preventDefault();
    var name = $('key-name').value.trim();
    var scopes = $('key-scopes').value.split(/[\s,]+/).filter(Boolean);
    if (!name || !scopes.length) return show('A name and at least one scope are required.', true);
    try {
      var result = await api('/admin/v1/api-keys', { method: 'POST', body: { name: name, scopes: Array.from(new Set(scopes)) } });
      $('new-secret').textContent = result.api_key;
      $('secret-panel').hidden = false;
      $('key-form').reset();
      show('API key created. Copy its secret now.');
      await Promise.all([loadKeys(), loadAudit()]);
    } catch (error) { show(error.message, true); }
  }

  async function revokeKey(key) {
    if (!window.confirm('Revoke API key "' + key.name + '"? Clients using it will immediately lose access.')) return;
    try {
      await api('/admin/v1/api-keys/' + encodeURIComponent(key.id), { method: 'DELETE' });
      show('API key "' + key.name + '" revoked.');
      await Promise.all([loadKeys(), loadAudit()]);
    } catch (error) { show(error.message, true); }
  }

  async function copySecret() {
    var secret = $('new-secret').textContent;
    try {
      await navigator.clipboard.writeText(secret);
      show('API key copied to the clipboard.');
    } catch (_) {
      var range = document.createRange();
      range.selectNodeContents($('new-secret'));
      window.getSelection().removeAllRanges();
      window.getSelection().addRange(range);
      show('Secret selected. Press Ctrl/Cmd+C to copy.');
    }
  }

  async function invalidateCache(event) {
    event.preventDefault();
    var route = $('cache-route').value;
    if (!window.confirm('Invalidate ' + (route ? 'cached responses for ' + route : 'the complete gateway cache') + '?')) return;
    try {
      var result = await api('/admin/v1/cache/invalidate', { method: 'POST', body: { route: route } });
      show(result.deleted + ' cache ' + (result.deleted === 1 ? 'entry' : 'entries') + ' invalidated.');
      await loadAudit();
    } catch (error) { show(error.message, true); }
  }

  function renderAudit(data) {
    var body = $('audit-body');
    body.replaceChildren();
    if (!data.events || !data.events.length) {
      var row = make('tr');
      var cell = make('td', 'empty', 'No administrative events recorded.');
      cell.colSpan = 4;
      row.append(cell);
      body.append(row);
    } else {
      data.events.forEach(function (event) {
        var row = make('tr');
        row.append(make('td', '', formatDate(event.at)), make('td', '', event.actor), make('td', '', event.action), make('td', '', event.target || '—'));
        body.append(row);
      });
    }
    $('audit-page').textContent = 'Page ' + (model.auditPage + 1);
    $('audit-previous').disabled = model.auditPage === 0;
    $('audit-next').disabled = !data.next_cursor;
  }

  async function loadAudit(page) {
    if (page === undefined) {
      page = 0;
      model.auditCursors = [''];
    }
    if (page < 0 || page >= model.auditCursors.length) return;
    try {
      var cursor = model.auditCursors[page];
      var data = await api('/admin/v1/audit?limit=25' + (cursor ? '&before=' + encodeURIComponent(cursor) : ''));
      model.auditPage = page;
      model.auditCursors = model.auditCursors.slice(0, page + 1);
      if (data.next_cursor) model.auditCursors.push(data.next_cursor);
      renderAudit(data);
    }
    catch (error) { show(error.message, true); }
  }

  function bind() {
    $('refresh').addEventListener('click', function () { Promise.all([loadStatus(), loadStatistics(), loadVersions(), loadKeys(), loadAudit(), loadDynamicDNS()]); });
    $('refresh-audit').addEventListener('click', function () { loadAudit(); });
    $('audit-previous').addEventListener('click', function () { loadAudit(model.auditPage - 1); });
    $('audit-next').addEventListener('click', function () { loadAudit(model.auditPage + 1); });
    $('new-config').addEventListener('click', newConfig);
    $('add-route').addEventListener('click', function () { openRoute(''); });
    $('route-form').addEventListener('submit', saveRoute);
    $('close-route').addEventListener('click', function () { $('route-dialog').close(); });
    $('cancel-route').addEventListener('click', function () { $('route-dialog').close(); });
    $('route-dialog').addEventListener('click', function (event) { if (event.target === $('route-dialog')) $('route-dialog').close(); });
    $('format-config').addEventListener('click', function () { try { $('config-editor').value = JSON.stringify(editorJSON(), null, 2); show('Configuration formatted.'); } catch (error) { show(error.message, true); } });
    $('validate-config').addEventListener('click', validateConfig);
    $('save-config').addEventListener('click', saveConfig);
    $('key-form').addEventListener('submit', createKey);
    $('ddns-form').addEventListener('submit', saveDynamicDNS);
    $('copy-secret').addEventListener('click', copySecret);
    $('dismiss-secret').addEventListener('click', function () { $('new-secret').textContent = ''; $('secret-panel').hidden = true; });
    $('cache-form').addEventListener('submit', invalidateCache);
    document.querySelectorAll('.nav-link').forEach(function (link) {
      link.addEventListener('click', function () {
        document.querySelectorAll('.nav-link').forEach(function (item) { item.classList.toggle('active', item === link); });
      });
    });
    document.addEventListener('visibilitychange', function () { if (!document.hidden) loadStatus(true); });
  }

  async function initialize() {
    bind();
    await Promise.all([loadStatus(true), loadStatistics(true), loadVersions(), loadKeys(), loadAudit(), loadDynamicDNS()]);
    if (model.active) await loadConfig(model.active);
    window.setInterval(function () { if (!document.hidden) Promise.all([loadStatus(true), loadStatistics(true)]); }, 15000);
  }

  initialize().catch(function (error) { setConnection(false); show(error.message, true); });
}());
`
