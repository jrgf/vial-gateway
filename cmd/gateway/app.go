package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrgf/go-vial"
	"github.com/jrgf/go-vial/middleware"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker/v2"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	apiKeyHeader = "X-API-Key"
	cachePrefix  = "vial-gateway:cache:"
)

var errUpstreamStatus = errors.New("upstream server error")

type requestFault struct {
	status  int
	code    string
	message string
}

func (fault requestFault) Error() string { return fault.message }

type gatewayApp struct {
	*vial.App
	configuration applicationConfig
	manager       *routerManager
	redis         *redis.Client
	control       *controlPlane
}

type routerManager struct {
	current          atomic.Pointer[routerSnapshot]
	redisVersion     atomic.Int64
	redis            *redis.Client
	metrics          gatewayMetrics
	logger           *slog.Logger
	environment      string
	allowNoRoutes    bool
	dynamicDNSBearer string
}

type routerSnapshot struct {
	config GatewayConfig
	mux    *http.ServeMux
	ctx    context.Context
	cancel context.CancelFunc
	pools  []*upstreamPool
}

type gatewayMetrics struct {
	registry     *prometheus.Registry
	requests     *prometheus.CounterVec
	upstream     *prometheus.CounterVec
	reloads      *prometheus.CounterVec
	rateFailOpen prometheus.Counter
	cache        *prometheus.CounterVec
	dynamicDNS   *prometheus.CounterVec
}

type compiledRoute struct {
	config       routeConfig
	pool         *upstreamPool
	auth         *compiledAuth
	rate         *ratePolicy
	cache        *cachePolicy
	sem          chan struct{}
	trusted      []*net.IPNet
	redis        *redis.Client
	metrics      *gatewayMetrics
	transport    http.RoundTripper
	maxHeader    int
	jwtRefreshMu sync.Mutex
}

type compiledAuth struct {
	policy authPolicy
	keys   map[[32]byte]principal
	jwksMu sync.RWMutex
	jwks   jwk.Set
	jwksAt time.Time
}

type principal struct {
	ID     string
	Scopes map[string]bool
}

type upstreamPool struct {
	name      string
	endpoints []*upstreamEndpoint
	next      atomic.Uint64
}

type upstreamEndpoint struct {
	url     *url.URL
	healthy atomic.Bool
	breaker *gobreaker.CircuitBreaker[*http.Response]
}

type cachedResponse struct {
	Status int         `json:"status"`
	Header http.Header `json:"header"`
	Body   []byte      `json:"body"`
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(data)
}

func newApp(configuration applicationConfig) (*gatewayApp, error) {
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	metrics := newGatewayMetrics()
	var redisClient *redis.Client
	if configuration.RedisURL != "" {
		options, err := redis.ParseURL(configuration.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("parse Redis URL: %w", err)
		}
		redisClient = redis.NewClient(options)
	}
	manager := &routerManager{redis: redisClient, metrics: metrics, logger: slog.Default(), environment: configuration.Environment, allowNoRoutes: configuration.ControlOnly, dynamicDNSBearer: configuration.DynamicDNSBearerToken}
	if err := manager.Activate(configuration.Gateway); err != nil {
		return nil, err
	}

	app := vial.New()
	app.Use(middleware.RequestID(), forwardRequestID(), middleware.Logger(), middleware.Recover())
	app.Health("/health/live")
	app.Readiness("/health/ready", manager.readiness)
	app.HandleHTTP("/metrics", promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{}), vial.RouteName("metrics"))
	gateway := &gatewayApp{App: app, configuration: configuration, manager: manager, redis: redisClient}
	if configuration.Admin.Enabled {
		control, err := newControlPlane(configuration.Admin, redisClient, manager)
		if err != nil {
			return nil, err
		}
		gateway.control = control
		app.HandleHTTP("/admin", control, vial.RouteName("admin"))
		app.HandleHTTP("/admin/", control, vial.RouteName("admin.subtree"))
	}
	app.HandleHTTP("/", manager, vial.RouteName("gateway.dynamic"))
	return gateway, nil
}

func newGatewayMetrics() gatewayMetrics {
	metrics := gatewayMetrics{
		registry:     prometheus.NewRegistry(),
		requests:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vial_gateway_requests_total", Help: "Gateway requests by route and status."}, []string{"route", "status"}),
		upstream:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vial_gateway_upstream_attempts_total", Help: "Upstream attempts by route, endpoint, and result."}, []string{"route", "endpoint", "result"}),
		reloads:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vial_gateway_reloads_total", Help: "Configuration activations by result."}, []string{"result"}),
		rateFailOpen: prometheus.NewCounter(prometheus.CounterOpts{Name: "vial_gateway_rate_limit_fail_open_total", Help: "Rate-limit checks skipped because Redis was unavailable."}),
		cache:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vial_gateway_cache_total", Help: "Gateway cache outcomes."}, []string{"route", "result"}),
		dynamicDNS:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "vial_gateway_dynamic_dns_updates_total", Help: "Dynamic DNS checks by result."}, []string{"result"}),
	}
	metrics.registry.MustRegister(metrics.requests, metrics.upstream, metrics.reloads, metrics.rateFailOpen, metrics.cache, metrics.dynamicDNS)
	return metrics
}

func (manager *routerManager) Activate(configuration GatewayConfig) error {
	snapshot, err := manager.compile(configuration)
	if err != nil {
		manager.metrics.reloads.WithLabelValues("rejected").Inc()
		return err
	}
	previous := manager.current.Swap(snapshot)
	if previous != nil {
		previous.cancel()
	}
	if configuration.DynamicDNS.Enabled {
		go newDynamicDNSWorker(configuration.DynamicDNS, manager.dynamicDNSBearer, &manager.metrics, manager.logger).run(snapshot.ctx)
	}
	manager.metrics.reloads.WithLabelValues("activated").Inc()
	manager.logger.Info("gateway configuration activated", "version", configuration.Version)
	return nil
}

func (manager *routerManager) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	snapshot := manager.current.Load()
	if snapshot == nil {
		writeFault(writer, http.StatusServiceUnavailable, "not_configured", "No valid gateway configuration is active")
		return
	}
	snapshot.mux.ServeHTTP(writer, request)
}

func (manager *routerManager) readiness(context.Context) error {
	snapshot := manager.current.Load()
	if snapshot == nil {
		return errors.New("no active gateway configuration")
	}
	for _, pool := range snapshot.pools {
		if !pool.hasHealthy() {
			return fmt.Errorf("route %s has no healthy upstream", pool.name)
		}
	}
	return nil
}

func (manager *routerManager) compile(configuration GatewayConfig) (_ *routerSnapshot, err error) {
	if err := configuration.Validate(manager.environment, manager.allowNoRoutes); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	snapshot := &routerSnapshot{config: configuration, mux: http.NewServeMux(), ctx: ctx, cancel: cancel}
	defer func() {
		if recovered := recover(); recovered != nil {
			cancel()
			err = fmt.Errorf("route conflict: %v", recovered)
		}
	}()
	trusted, err := parseTrustedProxies(configuration.TrustedProxies)
	if err != nil {
		cancel()
		return nil, err
	}
	for _, route := range configuration.Routes {
		compiled, err := compileRoute(ctx, route, configuration, trusted, manager.redis, &manager.metrics)
		if err != nil {
			cancel()
			return nil, err
		}
		snapshot.pools = append(snapshot.pools, compiled.pool)
		handler := otelhttp.NewHandler(http.HandlerFunc(compiled.serveHTTP), route.Name)
		for _, pattern := range routePatterns(route) {
			snapshot.mux.Handle(pattern, handler)
		}
	}
	if len(configuration.CORSAllowedOrigins) > 0 {
		inner := snapshot.mux
		snapshot.mux = http.NewServeMux()
		snapshot.mux.Handle("/", corsHandler(configuration.CORSAllowedOrigins, inner))
	}
	return snapshot, nil
}

func compileRoute(ctx context.Context, route routeConfig, gateway GatewayConfig, trusted []*net.IPNet, redisClient *redis.Client, metrics *gatewayMetrics) (*compiledRoute, error) {
	normalizeRoute(&route)
	pool := &upstreamPool{name: route.Name}
	for _, raw := range route.Upstreams {
		endpointURL, _ := parseHTTPURL(route.Name+" upstream", raw)
		failures := route.CircuitBreaker.Failures
		endpoint := &upstreamEndpoint{url: endpointURL}
		endpoint.healthy.Store(true)
		endpoint.breaker = gobreaker.NewCircuitBreaker[*http.Response](gobreaker.Settings{
			Name:        route.Name + ":" + endpointURL.Host,
			Timeout:     route.CircuitBreaker.OpenFor.value(),
			ReadyToTrip: func(counts gobreaker.Counts) bool { return counts.ConsecutiveFailures >= failures },
			IsExcluded: func(err error) bool {
				return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
			},
		})
		pool.endpoints = append(pool.endpoints, endpoint)
	}
	compiled := &compiledRoute{
		config: route, pool: pool, trusted: trusted, redis: redisClient, metrics: metrics,
		transport: defaultTransport(), maxHeader: gateway.MaxHeaderBytes,
	}
	if route.Concurrency > 0 {
		compiled.sem = make(chan struct{}, route.Concurrency)
	}
	if route.AuthPolicy != "" {
		policy := gateway.AuthPolicies[route.AuthPolicy]
		compiled.auth = &compiledAuth{policy: policy, keys: map[[32]byte]principal{}}
		for _, key := range policy.Keys {
			decoded, _ := hashBytes(key.SHA256)
			var hash [32]byte
			copy(hash[:], decoded)
			compiled.auth.keys[hash] = principal{ID: key.Name, Scopes: scopeSet(key.Scopes)}
		}
	}
	if route.RatePolicy != "" {
		value := gateway.RatePolicies[route.RatePolicy]
		compiled.rate = &value
	}
	if route.CachePolicy != "" {
		value := gateway.CachePolicies[route.CachePolicy]
		compiled.cache = &value
	}
	if route.HealthPath != "" {
		pool.startHealthChecks(ctx, route.HealthPath, route.HealthInterval.value())
	}
	return compiled, nil
}

func normalizeRoute(route *routeConfig) {
	if route.Timeout.value() == 0 {
		route.Timeout = duration(15 * time.Second)
	}
	if route.MaxBodyBytes == 0 {
		route.MaxBodyBytes = 1 << 20
	}
	if route.HealthInterval.value() == 0 {
		route.HealthInterval = duration(10 * time.Second)
	}
	if route.CircuitBreaker.Failures == 0 {
		route.CircuitBreaker.Failures = 5
	}
	if route.CircuitBreaker.OpenFor.value() == 0 {
		route.CircuitBreaker.OpenFor = duration(30 * time.Second)
	}
	if route.PathRewrite == "" {
		route.PathRewrite = route.PathPrefix
	}
}

func routePatterns(route routeConfig) []string {
	methods := route.Methods
	if len(methods) == 0 {
		methods = []string{""}
	}
	hosts := route.Hosts
	if len(hosts) == 0 {
		hosts = []string{""}
	}
	base := strings.TrimSuffix(route.PathPrefix, "/")
	if base == "" {
		base = "/"
	}
	patterns := make([]string, 0, len(methods)*len(hosts)*2)
	for _, method := range methods {
		if method != "" {
			method = strings.ToUpper(method) + " "
		}
		for _, host := range hosts {
			if base == "/" {
				patterns = append(patterns, method+strings.ToLower(host)+"/")
				continue
			}
			patterns = append(patterns, method+strings.ToLower(host)+base, method+strings.ToLower(host)+base+"/")
		}
	}
	return patterns
}

func (route *compiledRoute) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	status := &statusWriter{ResponseWriter: writer}
	defer func() {
		code := status.status
		if code == 0 {
			code = http.StatusOK
		}
		route.metrics.requests.WithLabelValues(route.config.Name, strconv.Itoa(code)).Inc()
	}()
	if route.maxHeader > 0 && headerBytes(request.Header) > route.maxHeader {
		writeFault(status, http.StatusRequestHeaderFieldsTooLarge, "headers_too_large", "Request headers exceed the route limit")
		return
	}
	if request.ContentLength > route.config.MaxBodyBytes {
		writeFault(status, http.StatusRequestEntityTooLarge, "body_too_large", "Request body exceeds the route limit")
		return
	}
	if request.Body != nil {
		request.Body = http.MaxBytesReader(status, request.Body, route.config.MaxBodyBytes)
	}
	if route.sem != nil {
		select {
		case route.sem <- struct{}{}:
			defer func() { <-route.sem }()
		default:
			writeFault(status, http.StatusTooManyRequests, "concurrency_limited", "The route concurrency limit is reached")
			return
		}
	}
	ctx, cancel := context.WithTimeout(request.Context(), route.config.Timeout.value())
	defer cancel()
	request = request.WithContext(ctx)
	identity, err := route.authenticate(request)
	if err != nil {
		writeFault(status, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	if !hasScopes(identity.Scopes, route.config.Scopes) {
		writeFault(status, http.StatusForbidden, "insufficient_scope", "Required scope is missing")
		return
	}
	if allowed := route.allowRequest(request, identity); !allowed {
		status.Header().Set("Retry-After", "1")
		writeFault(status, http.StatusTooManyRequests, "rate_limited", "The distributed rate limit is exceeded")
		return
	}
	cacheKey := route.cacheKey(request, identity)
	if cacheKey != "" && route.serveCached(status, request, cacheKey) {
		return
	}
	response, err := route.forward(request)
	if err != nil {
		var fault requestFault
		if errors.As(err, &fault) {
			writeFault(status, fault.status, fault.code, fault.message)
			return
		}
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			writeFault(status, http.StatusRequestEntityTooLarge, "body_too_large", "Request body exceeds the route limit")
			return
		}
		slog.ErrorContext(request.Context(), "proxy request failed", "route", route.config.Name, "error", err)
		writeFault(status, http.StatusBadGateway, "bad_gateway", "Upstream service is unavailable")
		return
	}
	defer func() { _ = response.Body.Close() }()
	route.writeResponse(status, request, response, cacheKey)
}

func (route *compiledRoute) authenticate(request *http.Request) (principal, error) {
	if route.auth == nil || route.auth.policy.Type == "none" {
		return principal{ID: "anonymous", Scopes: map[string]bool{}}, nil
	}
	if route.auth.policy.Type == "api_key" {
		value := request.Header.Get(apiKeyHeader)
		if value == "" {
			return principal{}, errors.New("a valid API key is required")
		}
		hash := sha256.Sum256([]byte(value))
		for expected, identity := range route.auth.keys {
			if subtle.ConstantTimeCompare(hash[:], expected[:]) == 1 {
				return identity, nil
			}
		}
		if route.redis != nil {
			record, err := route.redis.HGetAll(request.Context(), "vial-gateway:apikey:"+hex.EncodeToString(hash[:])).Result()
			if err == nil && record["revoked"] != "1" && record["name"] != "" {
				return principal{ID: record["name"], Scopes: scopeSet(splitSpace(record["scopes"]))}, nil
			}
		}
		return principal{}, errors.New("a valid API key is required")
	}
	value := strings.TrimSpace(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
	if value == "" {
		return principal{}, errors.New("a valid bearer token is required")
	}
	return route.verifyJWT(request.Context(), value)
}

func (route *compiledRoute) verifyJWT(ctx context.Context, raw string) (principal, error) {
	auth := route.auth
	auth.jwksMu.RLock()
	set, fetched := auth.jwks, auth.jwksAt
	auth.jwksMu.RUnlock()
	if set == nil || time.Since(fetched) > 5*time.Minute {
		route.jwtRefreshMu.Lock()
		auth.jwksMu.RLock()
		set, fetched = auth.jwks, auth.jwksAt
		auth.jwksMu.RUnlock()
		if set == nil || time.Since(fetched) > 5*time.Minute {
			fresh, err := jwk.Fetch(ctx, auth.policy.JWKSURL)
			if err != nil {
				route.jwtRefreshMu.Unlock()
				return principal{}, errors.New("JWT keys are unavailable")
			}
			auth.jwksMu.Lock()
			auth.jwks, auth.jwksAt = fresh, time.Now()
			auth.jwksMu.Unlock()
			set = fresh
		}
		route.jwtRefreshMu.Unlock()
	}
	token, err := jwt.ParseString(raw, jwt.WithKeySet(set), jwt.WithValidate(true))
	if err != nil {
		return principal{}, errors.New("bearer token is invalid")
	}
	if err := jwt.Validate(token, jwt.WithIssuer(auth.policy.Issuer)); err != nil {
		return principal{}, errors.New("bearer token claims are invalid")
	}
	audiences, ok := token.Audience()
	if !ok || !audienceMatches(audiences, auth.policy.Audiences) {
		return principal{}, errors.New("bearer token audience is invalid")
	}
	subject, ok := token.Subject()
	if !ok || subject == "" {
		return principal{}, errors.New("bearer token subject is missing")
	}
	var scope string
	_ = token.Get("scope", &scope)
	scopes := splitSpace(scope)
	if len(scopes) == 0 {
		var scp []string
		_ = token.Get("scp", &scp)
		scopes = scp
	}
	return principal{ID: subject, Scopes: scopeSet(scopes)}, nil
}

const tokenBucketScript = `
local now = redis.call('TIME')
local ms = now[1] * 1000 + math.floor(now[2] / 1000)
local values = redis.call('HMGET', KEYS[1], 'tokens', 'updated')
local tokens = tonumber(values[1]) or tonumber(ARGV[1])
local updated = tonumber(values[2]) or ms
tokens = math.min(tonumber(ARGV[1]), tokens + (ms - updated) * tonumber(ARGV[2]) / tonumber(ARGV[3]))
local allowed = 0
if tokens >= 1 then tokens = tokens - 1; allowed = 1 end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated', ms)
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[3]) * 2)
return allowed`

func (route *compiledRoute) allowRequest(request *http.Request, identity principal) bool {
	if route.rate == nil {
		return true
	}
	if route.redis == nil {
		route.metrics.rateFailOpen.Inc()
		slog.WarnContext(request.Context(), "rate limit failed open", "route", route.config.Name, "error", "Redis is not configured")
		return true
	}
	keyID := identity.ID
	if keyID == "anonymous" {
		keyID = clientIP(request, route.trusted)
	}
	capacity := route.rate.Requests + route.rate.Burst
	key := fmt.Sprintf("vial-gateway:rate:%s:%s", route.config.Name, sha256Text(keyID))
	allowed, err := route.redis.Eval(request.Context(), tokenBucketScript, []string{key}, capacity, route.rate.Requests, route.rate.Window.value().Milliseconds()).Int()
	if err != nil {
		route.metrics.rateFailOpen.Inc()
		slog.WarnContext(request.Context(), "rate limit failed open", "route", route.config.Name, "error", err)
		return true
	}
	return allowed == 1
}

func (route *compiledRoute) forward(request *http.Request) (*http.Response, error) {
	var body []byte
	if !route.config.Streaming && request.Body != nil {
		var err error
		body, err = readBounded(request.Body, route.config.MaxBodyBytes)
		if err != nil {
			return nil, requestFault{status: http.StatusRequestEntityTooLarge, code: "body_too_large", message: "Request body exceeds the route limit"}
		}
		if !route.config.RequestTransform.JSON.empty() && len(body) > 0 {
			body, err = transformJSON(body, route.config.RequestTransform.JSON)
			if err != nil {
				return nil, requestFault{status: http.StatusBadRequest, code: "invalid_json", message: "Request body must be a JSON object"}
			}
		}
	}
	attempts := 1
	if isIdempotent(request.Method) && !route.config.Streaming {
		attempts += route.config.Retries
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		endpoint := route.pool.pick()
		if endpoint == nil {
			return nil, errors.New("no healthy upstream")
		}
		upstream := cloneUpstreamRequest(request, endpoint.url, route.config, body, route.trusted)
		response, err := endpoint.breaker.Execute(func() (*http.Response, error) {
			response, err := route.transport.RoundTrip(upstream)
			if err == nil && response.StatusCode >= 500 {
				return response, errUpstreamStatus
			}
			return response, err
		})
		result := "ok"
		if err != nil {
			result = "error"
		}
		route.metrics.upstream.WithLabelValues(route.config.Name, endpoint.url.Host, result).Inc()
		if err == nil {
			return response, nil
		}
		lastErr = err
		if response != nil {
			if attempt+1 == attempts {
				return response, nil
			}
			_ = response.Body.Close()
		}
	}
	return nil, lastErr
}

func cloneUpstreamRequest(request *http.Request, target *url.URL, route routeConfig, body []byte, trusted []*net.IPNet) *http.Request {
	upstream := request.Clone(request.Context())
	upstream.URL.Scheme = target.Scheme
	upstream.URL.Host = target.Host
	upstream.URL.Path = joinURLPath(target.Path, rewritePath(request.URL.Path, route.PathPrefix, route.PathRewrite))
	upstream.RequestURI = ""
	upstream.Host = target.Host
	removeHopHeaders(upstream.Header)
	upstream.Header.Del("Proxy-Authorization")
	applyHeaderTransform(upstream.Header, route.RequestTransform)
	setForwardedHeaders(upstream, request, trusted)
	if route.Streaming {
		upstream.Body = request.Body
	} else {
		upstream.Body = io.NopCloser(bytes.NewReader(body))
		upstream.ContentLength = int64(len(body))
	}
	return upstream
}

func (route *compiledRoute) writeResponse(writer http.ResponseWriter, request *http.Request, response *http.Response, key string) {
	removeHopHeaders(response.Header)
	response.Header.Del("Server")
	response.Header.Del("X-Powered-By")
	applyHeaderTransform(response.Header, route.config.ResponseTransform)
	if route.config.RewriteRedirects {
		rewriteRedirectLocation(response, route.config)
	}
	var body []byte
	buffer := key != "" || !route.config.ResponseTransform.JSON.empty()
	if buffer {
		limit := route.config.MaxBodyBytes
		if route.cache != nil && route.cache.MaxBodyBytes < limit {
			limit = route.cache.MaxBodyBytes
		}
		var err error
		body, err = readBounded(response.Body, limit)
		if err != nil {
			writeFault(writer, http.StatusBadGateway, "response_too_large", "Upstream response exceeds the configured limit")
			return
		}
		if !route.config.ResponseTransform.JSON.empty() && len(body) > 0 {
			body, err = transformJSON(body, route.config.ResponseTransform.JSON)
			if err != nil {
				writeFault(writer, http.StatusBadGateway, "invalid_upstream_json", "Upstream JSON transform failed")
				return
			}
		}
		response.Header.Del("Content-Length")
	}
	copyHeader(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	if request.Method != http.MethodHead {
		if buffer {
			_, _ = writer.Write(body)
		} else {
			_, _ = io.Copy(writer, response.Body)
		}
	}
	if key != "" && buffer {
		route.storeCached(request.Context(), key, response.StatusCode, response.Header, body)
	}
}

func (route *compiledRoute) cacheKey(request *http.Request, identity principal) string {
	if route.cache == nil || route.redis == nil || (request.Method != http.MethodGet && request.Method != http.MethodHead) {
		return ""
	}
	requestControl := strings.ToLower(request.Header.Get("Cache-Control"))
	if strings.Contains(requestControl, "no-cache") || strings.Contains(requestControl, "no-store") {
		return ""
	}
	parts := []string{route.config.Name, request.Method, request.URL.RequestURI()}
	if route.cache.PerPrincipal {
		parts = append(parts, identity.ID)
	}
	for _, header := range route.cache.VaryHeaders {
		parts = append(parts, textproto.CanonicalMIMEHeaderKey(header), request.Header.Get(header))
	}
	return cachePrefix + route.config.Name + ":" + sha256Text(strings.Join(parts, "\x00"))
}

func (route *compiledRoute) serveCached(writer http.ResponseWriter, request *http.Request, key string) bool {
	data, err := route.redis.Get(request.Context(), key).Bytes()
	if err != nil {
		route.metrics.cache.WithLabelValues(route.config.Name, "miss").Inc()
		return false
	}
	var cached cachedResponse
	if json.Unmarshal(data, &cached) != nil {
		return false
	}
	copyHeader(writer.Header(), cached.Header)
	writer.Header().Set("X-Cache", "HIT")
	writer.WriteHeader(cached.Status)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(cached.Body)
	}
	route.metrics.cache.WithLabelValues(route.config.Name, "hit").Inc()
	return true
}

func (route *compiledRoute) storeCached(ctx context.Context, key string, status int, header http.Header, body []byte) {
	if status != http.StatusOK || len(body) > int(route.cache.MaxBodyBytes) || header.Get("Set-Cookie") != "" {
		return
	}
	control := strings.ToLower(header.Get("Cache-Control"))
	if strings.Contains(control, "no-store") || strings.Contains(control, "private") {
		return
	}
	ttl := route.cache.TTL.value()
	if maxAge := cacheMaxAge(control); maxAge > 0 && maxAge < ttl {
		ttl = maxAge
	}
	encoded, err := json.Marshal(cachedResponse{Status: status, Header: header.Clone(), Body: body})
	if err == nil {
		if err = route.redis.Set(ctx, key, encoded, ttl).Err(); err == nil {
			route.metrics.cache.WithLabelValues(route.config.Name, "stored").Inc()
		}
	}
}

func (pool *upstreamPool) pick() *upstreamEndpoint {
	count := uint64(len(pool.endpoints))
	start := pool.next.Add(1) - 1
	for offset := uint64(0); offset < count; offset++ {
		endpoint := pool.endpoints[(start+offset)%count]
		if endpoint.healthy.Load() {
			return endpoint
		}
	}
	return nil
}

func (pool *upstreamPool) hasHealthy() bool {
	for _, endpoint := range pool.endpoints {
		if endpoint.healthy.Load() {
			return true
		}
	}
	return false
}

func (pool *upstreamPool) startHealthChecks(ctx context.Context, healthPath string, interval time.Duration) {
	client := &http.Client{Timeout: 2 * time.Second}
	for _, endpoint := range pool.endpoints {
		endpoint := endpoint
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			check := func() {
				urlValue := *endpoint.url
				urlValue.Path = joinURLPath(endpoint.url.Path, healthPath)
				request, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlValue.String(), nil)
				response, err := client.Do(request)
				healthy := false
				if response != nil {
					healthy = err == nil && response.StatusCode >= 200 && response.StatusCode < 400
					_ = response.Body.Close()
				}
				endpoint.healthy.Store(healthy)
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					check()
				}
			}
		}()
	}
}

func defaultTransport() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 15 * time.Second
	transport.MaxIdleConnsPerHost = 64
	return transport
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	trusted := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
				ip = ip.To4()
			}
			trusted = append(trusted, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, err
		}
		trusted = append(trusted, network)
	}
	return trusted, nil
}

func setForwardedHeaders(upstream, original *http.Request, trusted []*net.IPNet) {
	remote, _, _ := net.SplitHostPort(original.RemoteAddr)
	if !isTrusted(net.ParseIP(remote), trusted) {
		upstream.Header.Del("X-Forwarded-For")
	}
	if previous := upstream.Header.Get("X-Forwarded-For"); previous != "" {
		upstream.Header.Set("X-Forwarded-For", previous+", "+remote)
	} else {
		upstream.Header.Set("X-Forwarded-For", remote)
	}
	upstream.Header.Set("X-Forwarded-Host", original.Host)
	proto := "http"
	if original.TLS != nil {
		proto = "https"
	}
	upstream.Header.Set("X-Forwarded-Proto", proto)
}

func clientIP(request *http.Request, trusted []*net.IPNet) string {
	remote, _, _ := net.SplitHostPort(request.RemoteAddr)
	if isTrusted(net.ParseIP(remote), trusted) {
		values := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
		if len(values) > 0 && net.ParseIP(strings.TrimSpace(values[0])) != nil {
			return strings.TrimSpace(values[0])
		}
	}
	return remote
}

func isTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, network := range trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func transformJSON(data []byte, transform jsonTransform) ([]byte, error) {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, errors.New("body must be a JSON object")
	}
	for _, key := range transform.Remove {
		delete(object, key)
	}
	for from, to := range transform.Rename {
		if value, ok := object[from]; ok {
			object[to] = value
			delete(object, from)
		}
	}
	for key, value := range transform.Add {
		object[key] = value
	}
	return json.Marshal(object)
}

func applyHeaderTransform(header http.Header, transform transformConfig) {
	for _, name := range transform.RemoveHeaders {
		header.Del(name)
	}
	for name, value := range transform.SetHeaders {
		header.Set(name, value)
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("body exceeds configured limit")
	}
	return data, nil
}

func headerBytes(header http.Header) int {
	total := 0
	for key, values := range header {
		total += len(key)
		for _, value := range values {
			total += len(value)
		}
	}
	return total
}

func removeHopHeaders(header http.Header) {
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func copyHeader(destination, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func rewritePath(pathValue, prefix, replacement string) string {
	remainder := strings.TrimPrefix(pathValue, strings.TrimSuffix(prefix, "/"))
	return joinURLPath(replacement, remainder)
}

func joinURLPath(left, right string) string {
	if left == "" {
		left = "/"
	}
	return strings.TrimSuffix(left, "/") + "/" + strings.TrimPrefix(right, "/")
}

func rewriteRedirectLocation(response *http.Response, route routeConfig) {
	if response.Request == nil || response.Request.URL == nil {
		return
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || location.String() == "" {
		return
	}
	resolved := response.Request.URL.ResolveReference(location)
	if !strings.EqualFold(resolved.Host, response.Request.URL.Host) {
		return
	}
	path := resolved.Path
	rewrite := strings.TrimSuffix(route.PathRewrite, "/")
	if rewrite != "" && rewrite != "/" && (path == rewrite || strings.HasPrefix(path, rewrite+"/")) {
		path = strings.TrimPrefix(path, rewrite)
	}
	resolved.Scheme = ""
	resolved.Host = ""
	resolved.User = nil
	resolved.Path = joinURLPath(route.PathPrefix, path)
	resolved.RawPath = ""
	response.Header.Set("Location", resolved.String())
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

func scopeSet(scopes []string) map[string]bool {
	result := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope != "" {
			result[scope] = true
		}
	}
	return result
}

func hasScopes(actual map[string]bool, required []string) bool {
	for _, scope := range required {
		if !actual[scope] {
			return false
		}
	}
	return true
}

func audienceMatches(actual, expected []string) bool {
	for _, wanted := range expected {
		for _, value := range actual {
			if value == wanted {
				return true
			}
		}
	}
	return false
}

func splitSpace(value string) []string { return strings.Fields(strings.ReplaceAll(value, ",", " ")) }

func sha256Text(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func cacheMaxAge(control string) time.Duration {
	for directive := range strings.SplitSeq(control, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if ok && name == "max-age" {
			seconds, _ := strconv.Atoi(value)
			return time.Duration(math.Max(0, float64(seconds))) * time.Second
		}
	}
	return 0
}

func corsHandler(origins []string, next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, origin := range origins {
		allowed[origin] = true
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		origin := request.Header.Get("Origin")
		if origin != "" && (allowed[origin] || allowed["*"]) {
			writer.Header().Set("Access-Control-Allow-Origin", origin)
			writer.Header().Add("Vary", "Origin")
			writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, X-Request-ID")
			writer.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
			if request.Method == http.MethodOptions {
				writer.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(writer, request)
	})
}

func forwardRequestID() vial.Middleware {
	return func(next vial.Handler) vial.Handler {
		return func(context *vial.Context) error {
			context.Request().Header.Set(middleware.RequestIDHeader, middleware.RequestIDFromContext(context))
			return next(context)
		}
	}
}

func writeFault(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}
