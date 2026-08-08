package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

const (
	configKeyPrefix  = "vial-gateway:config:"
	activeConfigKey  = "vial-gateway:config:active"
	activationTopic  = "vial-gateway:config:activated"
	auditKey         = "vial-gateway:audit"
	sessionKeyPrefix = "vial-gateway:session:"
	adminCookie      = "vial_gateway_admin"
)

var (
	errConfigActive   = errors.New("active configuration cannot be deleted")
	errConfigNotFound = errors.New("configuration version does not exist")
)

type controlPlane struct {
	config        adminConfig
	redis         *redis.Client
	manager       *routerManager
	mux           *http.ServeMux
	metricsClient *http.Client
	oidcMu        sync.Mutex
	provider      *oidc.Provider
	verifier      *oidc.IDTokenVerifier
	oauth         *oauth2.Config
}

type adminSession struct {
	Subject  string   `json:"subject,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	CSRF     string   `json:"csrf,omitempty"`
	State    string   `json:"state,omitempty"`
	Verifier string   `json:"verifier,omitempty"`
}

type adminIdentity struct {
	Subject string
	CSRF    string
	Session bool
}

type createAPIKeyRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
}

type cacheInvalidationRequest struct {
	Route string `json:"route"`
}

func newControlPlane(configuration adminConfig, redisClient *redis.Client, manager *routerManager) (*controlPlane, error) {
	if redisClient == nil {
		return nil, errors.New("admin control plane requires Redis")
	}
	control := &controlPlane{config: configuration, redis: redisClient, manager: manager, mux: http.NewServeMux(), metricsClient: &http.Client{Timeout: 3 * time.Second}}
	control.mux.HandleFunc("GET /admin/assets/app.css", control.adminCSS)
	control.mux.HandleFunc("GET /admin/assets/app.js", control.adminJS)
	control.mux.HandleFunc("GET /admin/login", control.login)
	control.mux.HandleFunc("GET /admin/callback", control.callback)
	control.mux.HandleFunc("GET /admin", control.protect(control.dashboard))
	control.mux.HandleFunc("POST /admin/logout", control.protect(control.logout))
	control.mux.HandleFunc("GET /admin/v1/status", control.protect(control.status))
	control.mux.HandleFunc("GET /admin/v1/statistics", control.protect(control.statistics))
	control.mux.HandleFunc("POST /admin/v1/configs/validate", control.protect(control.validateConfig))
	control.mux.HandleFunc("POST /admin/v1/configs", control.protect(control.createConfig))
	control.mux.HandleFunc("GET /admin/v1/configs", control.protect(control.listConfigs))
	control.mux.HandleFunc("GET /admin/v1/configs/{version}", control.protect(control.getConfig))
	control.mux.HandleFunc("DELETE /admin/v1/configs/{version}", control.protect(control.deleteConfig))
	control.mux.HandleFunc("POST /admin/v1/configs/{version}/activate", control.protect(control.activateConfig("activate")))
	control.mux.HandleFunc("POST /admin/v1/configs/{version}/rollback", control.protect(control.activateConfig("rollback")))
	control.mux.HandleFunc("GET /admin/v1/api-keys", control.protect(control.listAPIKeys))
	control.mux.HandleFunc("POST /admin/v1/api-keys", control.protect(control.createAPIKey))
	control.mux.HandleFunc("DELETE /admin/v1/api-keys/{id}", control.protect(control.revokeAPIKey))
	control.mux.HandleFunc("POST /admin/v1/cache/invalidate", control.protect(control.invalidateCache))
	control.mux.HandleFunc("GET /admin/v1/audit", control.protect(control.listAudit))
	return control, nil
}

func (control *controlPlane) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	control.mux.ServeHTTP(writer, request)
}

func (control *controlPlane) protect(next func(http.ResponseWriter, *http.Request, adminIdentity)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		identity, err := control.authenticate(request)
		if err != nil {
			if request.URL.Path == "/admin" && control.config.OIDCIssuer != "" {
				http.Redirect(writer, request, "/admin/login", http.StatusFound)
				return
			}
			writeFault(writer, http.StatusUnauthorized, "admin_unauthorized", "gateway.admin scope is required")
			return
		}
		if identity.Session && request.Method != http.MethodGet && request.Method != http.MethodHead {
			token := request.Header.Get("X-CSRF-Token")
			if token == "" {
				token = request.FormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(identity.CSRF)) != 1 {
				writeFault(writer, http.StatusForbidden, "csrf_failed", "A valid CSRF token is required")
				return
			}
		}
		next(writer, request, identity)
	}
}

func (control *controlPlane) authenticate(request *http.Request) (adminIdentity, error) {
	secret := request.Header.Get(apiKeyHeader)
	if secret == "" {
		value := request.Header.Get("Authorization")
		if strings.HasPrefix(value, "Bearer ") {
			secret = strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
		}
	}
	if secret != "" {
		hash := sha256.Sum256([]byte(secret))
		if expected, err := hashBytes(control.config.BootstrapKeySHA); err == nil && subtle.ConstantTimeCompare(hash[:], expected) == 1 {
			return adminIdentity{Subject: "bootstrap"}, nil
		}
		record, err := control.redis.HGetAll(request.Context(), "vial-gateway:apikey:"+hex.EncodeToString(hash[:])).Result()
		if err == nil && record["revoked"] != "1" && scopeSet(splitSpace(record["scopes"]))["gateway.admin"] {
			return adminIdentity{Subject: record["name"]}, nil
		}
	}
	cookie, err := request.Cookie(adminCookie)
	if err != nil {
		return adminIdentity{}, err
	}
	data, err := control.redis.Get(request.Context(), sessionKeyPrefix+cookie.Value).Bytes()
	if err != nil {
		return adminIdentity{}, err
	}
	var session adminSession
	if json.Unmarshal(data, &session) != nil || !scopeSet(session.Scopes)["gateway.admin"] {
		return adminIdentity{}, errors.New("invalid session")
	}
	return adminIdentity{Subject: session.Subject, CSRF: session.CSRF, Session: true}, nil
}

func (control *controlPlane) validateConfig(writer http.ResponseWriter, request *http.Request, _ adminIdentity) {
	configuration, err := decodeGatewayConfig(writer, request)
	if err != nil {
		return
	}
	if err = control.validateGatewayConfig(configuration); err != nil {
		writeFault(writer, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"valid": true, "version": configuration.Version})
}

func (control *controlPlane) createConfig(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
	configuration, err := decodeGatewayConfig(writer, request)
	if err != nil {
		return
	}
	if err = control.validateGatewayConfig(configuration); err != nil {
		writeFault(writer, http.StatusUnprocessableEntity, "invalid_config", err.Error())
		return
	}
	encoded, _ := json.Marshal(configuration)
	created, err := control.redis.SetNX(request.Context(), configKey(configuration.Version), encoded, 0).Result()
	if err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	if !created {
		writeFault(writer, http.StatusConflict, "version_exists", "Configuration versions are immutable")
		return
	}
	control.audit(request.Context(), identity.Subject, "config.create", strconv.FormatInt(configuration.Version, 10))
	writeJSON(writer, http.StatusCreated, map[string]any{"version": configuration.Version})
}

func (control *controlPlane) listConfigs(writer http.ResponseWriter, request *http.Request, _ adminIdentity) {
	active, err := control.redis.Get(request.Context(), activeConfigKey).Result()
	if err != nil && err != redis.Nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	versions := []int64{}
	var cursor uint64
	for {
		keys, next, err := control.redis.Scan(request.Context(), cursor, configKeyPrefix+"*", 100).Result()
		if err != nil {
			writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
			return
		}
		for _, key := range keys {
			version, err := strconv.ParseInt(strings.TrimPrefix(key, configKeyPrefix), 10, 64)
			if err == nil {
				versions = append(versions, version)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	writeJSON(writer, http.StatusOK, map[string]any{"active": active, "versions": versions})
}

func (control *controlPlane) deleteConfig(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
	version, err := strconv.ParseInt(request.PathValue("version"), 10, 64)
	if err != nil || version < 1 {
		writeFault(writer, http.StatusBadRequest, "invalid_version", "A positive version is required")
		return
	}
	key := configKey(version)
	err = control.redis.Watch(request.Context(), func(transaction *redis.Tx) error {
		active, err := transaction.Get(request.Context(), activeConfigKey).Result()
		if err != nil && err != redis.Nil {
			return err
		}
		if active == strconv.FormatInt(version, 10) {
			return errConfigActive
		}
		exists, err := transaction.Exists(request.Context(), key).Result()
		if err != nil {
			return err
		}
		if exists == 0 {
			return errConfigNotFound
		}
		_, err = transaction.TxPipelined(request.Context(), func(pipe redis.Pipeliner) error {
			pipe.Del(request.Context(), key)
			return nil
		})
		return err
	}, activeConfigKey, key)
	if err != nil {
		switch {
		case errors.Is(err, errConfigActive):
			writeFault(writer, http.StatusConflict, "config_active", errConfigActive.Error())
		case errors.Is(err, errConfigNotFound):
			writeFault(writer, http.StatusNotFound, "version_not_found", errConfigNotFound.Error())
		case errors.Is(err, redis.TxFailedErr):
			writeFault(writer, http.StatusConflict, "version_conflict", "Configuration state changed; retry the request")
		default:
			writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		}
		return
	}
	control.audit(request.Context(), identity.Subject, "config.delete", strconv.FormatInt(version, 10))
	writeJSON(writer, http.StatusOK, map[string]any{"deleted": true, "version": version})
}

func (control *controlPlane) activateConfig(action string) func(http.ResponseWriter, *http.Request, adminIdentity) {
	return func(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
		version, err := strconv.ParseInt(request.PathValue("version"), 10, 64)
		if err != nil || version < 1 {
			writeFault(writer, http.StatusBadRequest, "invalid_version", "A positive version is required")
			return
		}
		expected := strings.Trim(request.Header.Get("If-Match"), `"`)
		if expected == "" {
			writeFault(writer, http.StatusPreconditionRequired, "version_required", "If-Match must contain the current version")
			return
		}
		data, err := control.redis.Get(request.Context(), configKey(version)).Bytes()
		if err == redis.Nil {
			writeFault(writer, http.StatusNotFound, "version_not_found", "Configuration version does not exist")
			return
		}
		if err != nil {
			writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
			return
		}
		var configuration GatewayConfig
		if json.Unmarshal(data, &configuration) != nil || control.validateGatewayConfig(configuration) != nil {
			writeFault(writer, http.StatusUnprocessableEntity, "invalid_config", "Stored configuration is invalid")
			return
		}
		err = control.redis.Watch(request.Context(), func(transaction *redis.Tx) error {
			current, err := transaction.Get(request.Context(), activeConfigKey).Result()
			if err == redis.Nil {
				current = ""
			} else if err != nil {
				return err
			}
			if current != expected {
				return fmt.Errorf("version conflict: active is %s", current)
			}
			exists, err := transaction.Exists(request.Context(), configKey(version)).Result()
			if err != nil {
				return err
			}
			if exists == 0 {
				return errConfigNotFound
			}
			_, err = transaction.TxPipelined(request.Context(), func(pipe redis.Pipeliner) error {
				pipe.Set(request.Context(), activeConfigKey, strconv.FormatInt(version, 10), 0)
				pipe.Publish(request.Context(), activationTopic, strconv.FormatInt(version, 10))
				return nil
			})
			return err
		}, activeConfigKey, configKey(version))
		if err != nil {
			if errors.Is(err, errConfigNotFound) {
				writeFault(writer, http.StatusNotFound, "version_not_found", errConfigNotFound.Error())
				return
			}
			if strings.Contains(err.Error(), "version conflict") || errors.Is(err, redis.TxFailedErr) {
				writeFault(writer, http.StatusConflict, "version_conflict", err.Error())
				return
			}
			writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
			return
		}
		if err := control.manager.Activate(configuration); err != nil {
			writeFault(writer, http.StatusUnprocessableEntity, "invalid_config", err.Error())
			return
		}
		control.manager.redisVersion.Store(version)
		control.audit(request.Context(), identity.Subject, "config."+action, strconv.FormatInt(version, 10))
		writeJSON(writer, http.StatusOK, map[string]any{"active": version})
	}
}

func (control *controlPlane) validateGatewayConfig(configuration GatewayConfig) error {
	if err := configuration.Validate(control.manager.environment, false); err != nil {
		return err
	}
	return control.manager.Validate(configuration)
}

func (control *controlPlane) createAPIKey(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
	var input createAPIKeyRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		return
	}
	if strings.TrimSpace(input.Name) == "" || len(input.Scopes) == 0 {
		writeFault(writer, http.StatusUnprocessableEntity, "invalid_api_key", "name and scopes are required")
		return
	}
	secret, err := randomToken(32)
	if err != nil {
		writeFault(writer, http.StatusInternalServerError, "random_failed", "Could not generate API key")
		return
	}
	secret = "vgk_" + secret
	id := sha256Text(secret)
	err = control.redis.HSet(request.Context(), "vial-gateway:apikey:"+id, map[string]any{"name": input.Name, "scopes": strings.Join(input.Scopes, " "), "revoked": "0", "created_at": time.Now().UTC().Format(time.RFC3339Nano)}).Err()
	if err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	control.audit(request.Context(), identity.Subject, "apikey.create", id)
	writeJSON(writer, http.StatusCreated, map[string]any{"id": id, "api_key": secret, "name": input.Name, "scopes": input.Scopes})
}

func (control *controlPlane) revokeAPIKey(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
	id := request.PathValue("id")
	if _, err := hashBytes(id); err != nil {
		writeFault(writer, http.StatusBadRequest, "invalid_api_key", "API key id must be a SHA-256 value")
		return
	}
	key := "vial-gateway:apikey:" + id
	exists, err := control.redis.Exists(request.Context(), key).Result()
	if err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	if exists == 0 {
		writeFault(writer, http.StatusNotFound, "api_key_not_found", "API key does not exist")
		return
	}
	changed, err := control.redis.HSet(request.Context(), key, "revoked", "1", "revoked_at", time.Now().UTC().Format(time.RFC3339Nano)).Result()
	if err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	control.audit(request.Context(), identity.Subject, "apikey.revoke", id)
	writeJSON(writer, http.StatusOK, map[string]any{"revoked": changed >= 0, "id": id})
}

func (control *controlPlane) invalidateCache(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
	var input cacheInvalidationRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		return
	}
	pattern := cachePrefix + "*"
	if input.Route != "" {
		pattern = cachePrefix + input.Route + ":*"
	}
	deleted := int64(0)
	var cursor uint64
	for {
		keys, next, err := control.redis.Scan(request.Context(), cursor, pattern, 200).Result()
		if err != nil {
			writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
			return
		}
		if len(keys) > 0 {
			count, err := control.redis.Unlink(request.Context(), keys...).Result()
			if err != nil {
				writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
				return
			}
			deleted += count
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	control.audit(request.Context(), identity.Subject, "cache.invalidate", input.Route)
	writeJSON(writer, http.StatusOK, map[string]any{"deleted": deleted})
}

func (control *controlPlane) login(writer http.ResponseWriter, request *http.Request) {
	if external, err := url.Parse(control.config.ExternalURL); err == nil && external.Host != "" && request.Host != external.Host {
		external.Path = "/admin/login"
		external.RawQuery = ""
		external.Fragment = ""
		http.Redirect(writer, request, external.String(), http.StatusFound)
		return
	}
	if control.config.OIDCIssuer == "" {
		writeFault(writer, http.StatusNotFound, "oidc_disabled", "OIDC is not configured")
		return
	}
	if err := control.initOIDC(request.Context()); err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC provider is unavailable")
		return
	}
	state, err := randomToken(24)
	if err != nil {
		writeFault(writer, http.StatusInternalServerError, "random_failed", "Could not initialize OIDC login")
		return
	}
	verifier := oauth2.GenerateVerifier()
	id, err := randomToken(24)
	if err != nil {
		writeFault(writer, http.StatusInternalServerError, "random_failed", "Could not initialize OIDC login")
		return
	}
	data, _ := json.Marshal(adminSession{State: state, Verifier: verifier})
	if err := control.redis.Set(request.Context(), sessionKeyPrefix+id, data, 10*time.Minute).Err(); err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	control.setCookie(writer, id, 10*time.Minute)
	http.Redirect(writer, request, control.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (control *controlPlane) callback(writer http.ResponseWriter, request *http.Request) {
	if err := control.initOIDC(request.Context()); err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC provider is unavailable")
		return
	}
	cookie, err := request.Cookie(adminCookie)
	if err != nil {
		writeFault(writer, http.StatusBadRequest, "oidc_state", "OIDC state is missing")
		return
	}
	data, err := control.redis.GetDel(request.Context(), sessionKeyPrefix+cookie.Value).Bytes()
	if err != nil {
		writeFault(writer, http.StatusBadRequest, "oidc_state", "OIDC state expired")
		return
	}
	var pending adminSession
	if json.Unmarshal(data, &pending) != nil || subtle.ConstantTimeCompare([]byte(request.URL.Query().Get("state")), []byte(pending.State)) != 1 {
		writeFault(writer, http.StatusBadRequest, "oidc_state", "OIDC state is invalid")
		return
	}
	token, err := control.oauth.Exchange(request.Context(), request.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		writeFault(writer, http.StatusUnauthorized, "oidc_exchange", "OIDC authorization failed")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		writeFault(writer, http.StatusUnauthorized, "oidc_token", "OIDC ID token is missing")
		return
	}
	idToken, err := control.verifier.Verify(request.Context(), rawID)
	if err != nil {
		writeFault(writer, http.StatusUnauthorized, "oidc_token", "OIDC ID token is invalid")
		return
	}
	claims := struct {
		Subject string `json:"sub"`
		Scope   string `json:"scope"`
	}{}
	if idToken.Claims(&claims) != nil {
		writeFault(writer, http.StatusUnauthorized, "oidc_token", "OIDC claims are invalid")
		return
	}
	scopes := splitSpace(claims.Scope)
	if len(scopes) == 0 {
		if granted, ok := token.Extra("scope").(string); ok {
			scopes = splitSpace(granted)
		}
	}
	if !scopeSet(scopes)["gateway.admin"] {
		writeFault(writer, http.StatusForbidden, "insufficient_scope", "gateway.admin scope is required")
		return
	}
	csrf, err := randomToken(24)
	if err != nil {
		writeFault(writer, http.StatusInternalServerError, "random_failed", "Could not create admin session")
		return
	}
	sessionID, err := randomToken(32)
	if err != nil {
		writeFault(writer, http.StatusInternalServerError, "random_failed", "Could not create admin session")
		return
	}
	session := adminSession{Subject: claims.Subject, Scopes: scopes, CSRF: csrf}
	encoded, _ := json.Marshal(session)
	ttl := control.config.SessionTTL.value()
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	if err := control.redis.Set(request.Context(), sessionKeyPrefix+sessionID, encoded, ttl).Err(); err != nil {
		writeFault(writer, http.StatusServiceUnavailable, "control_unavailable", "Redis is unavailable")
		return
	}
	control.setCookie(writer, sessionID, ttl)
	control.audit(request.Context(), claims.Subject, "session.login", "")
	http.Redirect(writer, request, "/admin", http.StatusFound)
}

func (control *controlPlane) logout(writer http.ResponseWriter, request *http.Request, identity adminIdentity) {
	if cookie, err := request.Cookie(adminCookie); err == nil {
		if err := control.redis.Del(request.Context(), sessionKeyPrefix+cookie.Value).Err(); err != nil {
			control.manager.logger.Warn("delete admin session", "error", err)
		}
	}
	control.setCookie(writer, "", -time.Hour)
	control.audit(request.Context(), identity.Subject, "session.logout", "")
	http.Redirect(writer, request, "/admin", http.StatusFound)
}

func (control *controlPlane) initOIDC(ctx context.Context) error {
	control.oidcMu.Lock()
	defer control.oidcMu.Unlock()
	if control.provider != nil {
		return nil
	}
	provider, err := oidc.NewProvider(ctx, control.config.OIDCIssuer)
	if err != nil {
		return err
	}
	redirect := strings.TrimSuffix(control.config.ExternalURL, "/") + "/admin/callback"
	scopes := append([]string{oidc.ScopeOpenID}, control.config.OIDCScopes...)
	control.provider = provider
	control.verifier = provider.Verifier(&oidc.Config{ClientID: control.config.OIDCClientID})
	control.oauth = &oauth2.Config{ClientID: control.config.OIDCClientID, ClientSecret: control.config.OIDCClientSecret, Endpoint: provider.Endpoint(), RedirectURL: redirect, Scopes: scopes}
	return nil
}

func (control *controlPlane) setCookie(writer http.ResponseWriter, value string, ttl time.Duration) {
	secure := false
	if external, err := url.Parse(control.config.ExternalURL); err == nil {
		secure = external.Scheme == "https"
	}
	http.SetCookie(writer, &http.Cookie{Name: adminCookie, Value: value, Path: "/admin", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
}

func (control *controlPlane) audit(ctx context.Context, actor, action, target string) {
	if err := control.redis.XAdd(ctx, &redis.XAddArgs{Stream: auditKey, MaxLen: 10000, Approx: true, Values: map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "actor": actor, "action": action, "target": target}}).Err(); err != nil {
		control.manager.logger.Error("write admin audit event", "action", action, "error", err)
	}
}

func (manager *routerManager) Validate(configuration GatewayConfig) error {
	snapshot, err := manager.compile(configuration)
	if snapshot != nil {
		snapshot.cancel()
	}
	return err
}

func (gateway *gatewayApp) Start(ctx context.Context) {
	if gateway.redis == nil {
		return
	}
	if !gateway.configuration.ControlOnly {
		bootstrap, _ := json.Marshal(gateway.configuration.Gateway)
		if err := gateway.redis.SetNX(ctx, configKey(gateway.configuration.Gateway.Version), bootstrap, 0).Err(); err != nil {
			gateway.manager.logger.Warn("store bootstrap configuration", "error", err)
		}
		if err := gateway.redis.SetNX(ctx, activeConfigKey, strconv.FormatInt(gateway.configuration.Gateway.Version, 10), 0).Err(); err != nil {
			gateway.manager.logger.Warn("store active bootstrap version", "error", err)
		}
	}
	go gateway.manager.watch(ctx)
}

func (gateway *gatewayApp) Close() error {
	if snapshot := gateway.manager.current.Load(); snapshot != nil {
		snapshot.cancel()
	}
	if gateway.redis != nil {
		return gateway.redis.Close()
	}
	return nil
}

func (manager *routerManager) watch(ctx context.Context) {
	load := func() {
		version, err := manager.redis.Get(ctx, activeConfigKey).Int64()
		if err != nil {
			return
		}
		if manager.redisVersion.Load() == version {
			return
		}
		data, err := manager.redis.Get(ctx, configKey(version)).Bytes()
		if err != nil {
			return
		}
		var configuration GatewayConfig
		if json.Unmarshal(data, &configuration) == nil {
			if err := manager.Activate(configuration); err != nil {
				manager.logger.Error("reject activated configuration", "version", version, "error", err)
			} else {
				manager.redisVersion.Store(version)
			}
		}
	}
	load()
	pubsub := manager.redis.Subscribe(ctx, activationTopic)
	defer func() { _ = pubsub.Close() }()
	channel := pubsub.Channel()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			load()
		case _, ok := <-channel:
			if !ok {
				channel = nil
				continue
			}
			load()
		}
	}
}

func decodeGatewayConfig(writer http.ResponseWriter, request *http.Request) (GatewayConfig, error) {
	var configuration GatewayConfig
	err := decodeJSON(writer, request, &configuration)
	return configuration, err
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeFault(writer, http.StatusBadRequest, "invalid_json", err.Error())
		return err
	}
	return nil
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func configKey(version int64) string { return configKeyPrefix + strconv.FormatInt(version, 10) }

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
