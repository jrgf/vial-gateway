package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrgf/go-vial/config"
)

const gatewaySchemaVersion = 1

type duration time.Duration

func (d duration) value() time.Duration { return time.Duration(d) }

func (d *duration) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("duration must be a string such as 500ms or 2s")
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return err
	}
	*d = duration(parsed)
	return nil
}

func (d duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.value().String()) }

type applicationConfig struct {
	Environment           string        `json:"environment" env:"VIAL_ENV"`
	HTTP                  config.HTTP   `json:"http"`
	RedisURL              string        `json:"redis_url" env:"VIAL_REDIS_URL"`
	DynamicDNSBearerToken string        `json:"-" env:"VIAL_DYNAMIC_DNS_BEARER_TOKEN"`
	ControlOnly           bool          `json:"control_only" env:"VIAL_CONTROL_ONLY"`
	Admin                 adminConfig   `json:"admin"`
	TLS                   tlsConfig     `json:"tls"`
	Gateway               GatewayConfig `json:"gateway"`
}

type adminConfig struct {
	Enabled          bool     `json:"enabled" env:"VIAL_ADMIN_ENABLED"`
	ExternalURL      string   `json:"external_url" env:"VIAL_ADMIN_EXTERNAL_URL"`
	BootstrapKeySHA  string   `json:"bootstrap_key_sha256" env:"VIAL_ADMIN_BOOTSTRAP_KEY_SHA256"`
	OIDCIssuer       string   `json:"oidc_issuer" env:"VIAL_ADMIN_OIDC_ISSUER"`
	OIDCClientID     string   `json:"oidc_client_id" env:"VIAL_ADMIN_OIDC_CLIENT_ID"`
	OIDCClientSecret string   `json:"oidc_client_secret" env:"VIAL_ADMIN_OIDC_CLIENT_SECRET"`
	OIDCScopes       []string `json:"oidc_scopes"`
	PrometheusURL    string   `json:"prometheus_url" env:"VIAL_ADMIN_PROMETHEUS_URL"`
	SessionTTL       duration `json:"session_ttl"`
}

type tlsConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type GatewayConfig struct {
	SchemaVersion      int                    `json:"schema_version"`
	Version            int64                  `json:"version"`
	Routes             []routeConfig          `json:"routes"`
	AuthPolicies       map[string]authPolicy  `json:"auth_policies"`
	RatePolicies       map[string]ratePolicy  `json:"rate_policies"`
	CachePolicies      map[string]cachePolicy `json:"cache_policies"`
	Telemetry          telemetryConfig        `json:"telemetry"`
	DynamicDNS         dynamicDNSConfig       `json:"dynamic_dns"`
	TrustedProxies     []string               `json:"trusted_proxies"`
	CORSAllowedOrigins []string               `json:"cors_allowed_origins"`
	MaxHeaderBytes     int                    `json:"max_header_bytes"`
}

type routeConfig struct {
	Name              string               `json:"name"`
	Hosts             []string             `json:"hosts"`
	Methods           []string             `json:"methods"`
	PathPrefix        string               `json:"path_prefix"`
	PathRewrite       string               `json:"path_rewrite"`
	RewriteRedirects  bool                 `json:"rewrite_redirects"`
	Upstreams         []string             `json:"upstreams"`
	HealthPath        string               `json:"health_path"`
	HealthInterval    duration             `json:"health_interval"`
	Timeout           duration             `json:"timeout"`
	MaxBodyBytes      int64                `json:"max_body_bytes"`
	AuthPolicy        string               `json:"auth_policy"`
	Scopes            []string             `json:"scopes"`
	RatePolicy        string               `json:"rate_policy"`
	Concurrency       int                  `json:"concurrency"`
	Retries           int                  `json:"retries"`
	CircuitBreaker    circuitBreakerConfig `json:"circuit_breaker"`
	CachePolicy       string               `json:"cache_policy"`
	RequestTransform  transformConfig      `json:"request_transform"`
	ResponseTransform transformConfig      `json:"response_transform"`
	Streaming         bool                 `json:"streaming"`
}

type authPolicy struct {
	Type      string         `json:"type"`
	Keys      []staticAPIKey `json:"keys"`
	Issuer    string         `json:"issuer"`
	JWKSURL   string         `json:"jwks_url"`
	Audiences []string       `json:"audiences"`
}

type staticAPIKey struct {
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256"`
	Scopes []string `json:"scopes"`
}

type ratePolicy struct {
	Requests int      `json:"requests"`
	Burst    int      `json:"burst"`
	Window   duration `json:"window"`
}

type cachePolicy struct {
	TTL          duration `json:"ttl"`
	MaxBodyBytes int64    `json:"max_body_bytes"`
	PerPrincipal bool     `json:"per_principal"`
	VaryHeaders  []string `json:"vary_headers"`
}

type circuitBreakerConfig struct {
	Failures uint32   `json:"failures"`
	OpenFor  duration `json:"open_for"`
}

type transformConfig struct {
	SetHeaders    map[string]string `json:"set_headers"`
	RemoveHeaders []string          `json:"remove_headers"`
	JSON          jsonTransform     `json:"json"`
}

type jsonTransform struct {
	Add    map[string]any    `json:"add"`
	Remove []string          `json:"remove"`
	Rename map[string]string `json:"rename"`
}

type telemetryConfig struct {
	ServiceName  string `json:"service_name"`
	OTLPEndpoint string `json:"otlp_http_endpoint" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`
}

type dynamicDNSConfig struct {
	Enabled   bool     `json:"enabled"`
	CheckURL  string   `json:"check_url"`
	UpdateURL string   `json:"update_url"`
	Interval  duration `json:"interval"`
	Timeout   duration `json:"timeout"`
}

func defaultConfig() applicationConfig {
	return applicationConfig{
		Environment: "development",
		Admin:       adminConfig{SessionTTL: duration(8 * time.Hour)},
		Gateway: GatewayConfig{
			SchemaVersion:  gatewaySchemaVersion,
			MaxHeaderBytes: 1 << 20,
			Telemetry:      telemetryConfig{ServiceName: "vial-gateway"},
		},
	}
}

func (configuration applicationConfig) Validate() error {
	if strings.TrimSpace(configuration.Environment) == "" {
		return errors.New("environment is required")
	}
	if err := configuration.Gateway.Validate(configuration.Environment, configuration.ControlOnly); err != nil {
		return err
	}
	if configuration.RedisURL != "" {
		parsed, err := url.Parse(configuration.RedisURL)
		if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Host == "" {
			return errors.New("redis_url must be an absolute redis:// or rediss:// URL")
		}
	}
	if configuration.Admin.Enabled {
		if configuration.RedisURL == "" {
			return errors.New("admin requires redis_url")
		}
		if _, err := hashBytes(configuration.Admin.BootstrapKeySHA); configuration.Admin.BootstrapKeySHA != "" && err != nil {
			return errors.New("admin bootstrap_key_sha256 must contain 64 hexadecimal characters")
		}
		oidcFields := []string{configuration.Admin.OIDCIssuer, configuration.Admin.OIDCClientID}
		configured := 0
		for _, field := range oidcFields {
			if field != "" {
				configured++
			}
		}
		if configured != 0 && configured != len(oidcFields) {
			return errors.New("admin OIDC requires oidc_issuer and oidc_client_id")
		}
		if configured > 0 && configuration.Admin.ExternalURL == "" {
			return errors.New("admin OIDC requires external_url")
		}
		if configured > 0 && !scopeSet(configuration.Admin.OIDCScopes)["gateway.admin"] {
			return errors.New("admin OIDC scopes must include gateway.admin")
		}
		if configuration.Environment == "production" && configured == 0 {
			return errors.New("admin OIDC is required outside development")
		}
		if configuration.Admin.ExternalURL != "" {
			external, err := url.Parse(configuration.Admin.ExternalURL)
			if err != nil || external.Host == "" || (external.Scheme != "http" && external.Scheme != "https") {
				return errors.New("admin external_url must be an absolute HTTP or HTTPS URL")
			}
			if configuration.Environment == "production" && external.Scheme != "https" {
				return errors.New("admin external_url must use HTTPS outside development")
			}
		}
		if configuration.Admin.SessionTTL.value() <= 0 {
			return errors.New("admin session_ttl must be positive")
		}
		if configuration.Admin.PrometheusURL != "" {
			metrics, err := url.Parse(configuration.Admin.PrometheusURL)
			if err != nil || metrics.Host == "" || (metrics.Scheme != "http" && metrics.Scheme != "https") || metrics.User != nil || metrics.RawQuery != "" || metrics.Fragment != "" {
				return errors.New("admin prometheus_url must be an absolute HTTP or HTTPS URL without credentials, a query, or a fragment")
			}
		}
	}
	if (configuration.TLS.CertFile == "") != (configuration.TLS.KeyFile == "") {
		return errors.New("TLS cert_file and key_file must be configured together")
	}
	return nil
}

func (gateway GatewayConfig) Validate(environment string, allowNoRoutes bool) error {
	if gateway.SchemaVersion != gatewaySchemaVersion {
		return fmt.Errorf("unsupported gateway schema_version %d", gateway.SchemaVersion)
	}
	if gateway.Version < 1 {
		return errors.New("gateway version must be positive")
	}
	if len(gateway.Routes) == 0 && !allowNoRoutes {
		return errors.New("at least one route is required")
	}
	if gateway.MaxHeaderBytes < 0 {
		return errors.New("max_header_bytes cannot be negative")
	}
	for _, origin := range gateway.CORSAllowedOrigins {
		if origin == "*" && environment != "development" {
			return errors.New("wildcard CORS is development-only")
		}
	}
	for _, trusted := range gateway.TrustedProxies {
		if net.ParseIP(trusted) == nil {
			if _, _, err := net.ParseCIDR(trusted); err != nil {
				return fmt.Errorf("trusted proxy %q is not an IP address or CIDR", trusted)
			}
		}
	}
	if err := gateway.DynamicDNS.validate(environment); err != nil {
		return err
	}
	for name, policy := range gateway.AuthPolicies {
		if err := policy.validate(name); err != nil {
			return err
		}
	}
	for name, policy := range gateway.RatePolicies {
		if policy.Requests <= 0 || policy.Burst < 0 || policy.Window.value() <= 0 {
			return fmt.Errorf("rate policy %q requires positive requests/window and non-negative burst", name)
		}
	}
	for name, policy := range gateway.CachePolicies {
		if policy.TTL.value() <= 0 || policy.MaxBodyBytes <= 0 {
			return fmt.Errorf("cache policy %q requires positive ttl and max_body_bytes", name)
		}
	}
	seenNames := map[string]bool{}
	seenRoutes := map[string]string{}
	for i := range gateway.Routes {
		route := &gateway.Routes[i]
		if route.Name == "" || seenNames[route.Name] {
			return fmt.Errorf("route name %q is empty or duplicated", route.Name)
		}
		seenNames[route.Name] = true
		if !strings.HasPrefix(route.PathPrefix, "/") {
			return fmt.Errorf("route %q path_prefix must start with /", route.Name)
		}
		if route.PathRewrite != "" && !strings.HasPrefix(route.PathRewrite, "/") {
			return fmt.Errorf("route %q path_rewrite must start with /", route.Name)
		}
		if len(route.Upstreams) == 0 {
			return fmt.Errorf("route %q requires at least one upstream", route.Name)
		}
		for _, raw := range route.Upstreams {
			if _, err := parseHTTPURL(route.Name+" upstream", raw); err != nil {
				return err
			}
		}
		if route.Timeout.value() < 0 || route.MaxBodyBytes < 0 || route.Concurrency < 0 || route.Retries < 0 {
			return fmt.Errorf("route %q contains a negative limit", route.Name)
		}
		if route.AuthPolicy != "" {
			if _, ok := gateway.AuthPolicies[route.AuthPolicy]; !ok {
				return fmt.Errorf("route %q references unknown auth policy %q", route.Name, route.AuthPolicy)
			}
		}
		if route.RatePolicy != "" {
			if _, ok := gateway.RatePolicies[route.RatePolicy]; !ok {
				return fmt.Errorf("route %q references unknown rate policy %q", route.Name, route.RatePolicy)
			}
		}
		if route.CachePolicy != "" {
			cache, ok := gateway.CachePolicies[route.CachePolicy]
			if !ok {
				return fmt.Errorf("route %q references unknown cache policy %q", route.Name, route.CachePolicy)
			}
			if route.AuthPolicy != "" && !cache.PerPrincipal {
				return fmt.Errorf("route %q authenticated caching requires per_principal", route.Name)
			}
			if route.Streaming {
				return fmt.Errorf("route %q cannot combine streaming and caching", route.Name)
			}
		}
		if route.Streaming && (route.Retries > 0 || !route.RequestTransform.JSON.empty() || !route.ResponseTransform.JSON.empty()) {
			return fmt.Errorf("route %q streaming cannot use retries or body transforms", route.Name)
		}
		if route.RequestTransform.operations()+route.ResponseTransform.operations() > 128 {
			return fmt.Errorf("route %q has too many transform operations", route.Name)
		}
		methods := route.Methods
		if len(methods) == 0 {
			methods = []string{"*"}
		}
		hosts := route.Hosts
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		for _, method := range methods {
			method = strings.ToUpper(method)
			if method != "*" && method == http.MethodConnect {
				return fmt.Errorf("route %q cannot proxy CONNECT", route.Name)
			}
			for _, host := range hosts {
				key := method + "\x00" + strings.ToLower(host) + "\x00" + strings.TrimSuffix(route.PathPrefix, "/")
				if previous := seenRoutes[key]; previous != "" {
					return fmt.Errorf("routes %q and %q conflict", previous, route.Name)
				}
				seenRoutes[key] = route.Name
			}
		}
	}
	return nil
}

func (configuration dynamicDNSConfig) validate(environment string) error {
	if !configuration.Enabled {
		return nil
	}
	if !strings.Contains(configuration.UpdateURL, "{ip}") {
		return errors.New("dynamic_dns update_url must contain {ip}")
	}
	for name, raw := range map[string]string{"check_url": configuration.CheckURL, "update_url": configuration.UpdateURL} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("dynamic_dns %s must be an absolute HTTP or HTTPS URL without credentials or a fragment", name)
		}
		if environment == "production" && parsed.Scheme != "https" {
			return fmt.Errorf("dynamic_dns %s must use HTTPS in production", name)
		}
	}
	if configuration.Interval.value() < 10*time.Second {
		return errors.New("dynamic_dns interval must be at least 10s")
	}
	if configuration.Timeout.value() <= 0 || configuration.Timeout.value() > configuration.Interval.value() {
		return errors.New("dynamic_dns timeout must be positive and no greater than interval")
	}
	return nil
}

func (policy authPolicy) validate(name string) error {
	switch policy.Type {
	case "none":
	case "api_key":
		for _, key := range policy.Keys {
			if key.Name == "" {
				return fmt.Errorf("auth policy %q has unnamed key", name)
			}
			if _, err := hashBytes(key.SHA256); err != nil {
				return fmt.Errorf("auth policy %q key %q has invalid SHA-256", name, key.Name)
			}
		}
	case "jwt":
		if policy.Issuer == "" || policy.JWKSURL == "" || len(policy.Audiences) == 0 {
			return fmt.Errorf("JWT auth policy %q requires issuer, jwks_url, and audiences", name)
		}
		if _, err := parseHTTPURL(name+" JWKS", policy.JWKSURL); err != nil {
			return err
		}
	default:
		return fmt.Errorf("auth policy %q has unsupported type %q", name, policy.Type)
	}
	return nil
}

func (transform transformConfig) operations() int {
	return len(transform.SetHeaders) + len(transform.RemoveHeaders) + len(transform.JSON.Add) + len(transform.JSON.Remove) + len(transform.JSON.Rename)
}

func (transform jsonTransform) empty() bool {
	return len(transform.Add) == 0 && len(transform.Remove) == 0 && len(transform.Rename) == 0
}

func parseHTTPURL(name, raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("%s URL must be an absolute HTTP or HTTPS URL", name)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s URL cannot contain credentials, a query, or a fragment", name)
	}
	return parsed, nil
}

func hashBytes(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("invalid SHA-256")
	}
	return decoded, nil
}
