package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type provider struct {
	issuer, clientID, clientSecret, redirectURI string
	username, password                          string
	key                                         *rsa.PrivateKey
	mux                                         *http.ServeMux
	mu                                          sync.Mutex
	codes                                       map[string]authorizationCode
}

type authorizationCode struct {
	challenge, redirectURI, scope, subject string
	expires                                time.Time
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gateway demo login</title><style>body{font:16px system-ui;max-width:24rem;margin:5rem auto;padding:0 1rem}label,input,button{display:block;width:100%;box-sizing:border-box}input,button{padding:.7rem;margin:.3rem 0 1rem}.error{color:#b00020}</style></head><body><h1>Gateway demo login</h1>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}<form method="post">{{range $key,$value := .Fields}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}<label>Email<input name="username" type="email" autocomplete="username" required autofocus></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form><p>Development only. Never deploy this identity provider.</p></body></html>`))

func main() {
	port := env("OIDC_PORT", "25556")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		slog.Error("generate signing key", "error", err)
		os.Exit(1)
	}
	provider := newProvider(
		env("OIDC_ISSUER", "http://oidc.localhost:"+port),
		env("OIDC_CLIENT_ID", "vial-gateway"),
		env("OIDC_CLIENT_SECRET", "demo-secret"),
		env("OIDC_REDIRECT_URI", "http://127.0.0.1:8081/admin/callback"),
		env("OIDC_USERNAME", "admin@example.com"),
		env("OIDC_PASSWORD", "admin"),
		key,
	)
	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: provider, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("demo OIDC provider listening", "issuer", provider.issuer)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

func newProvider(issuer, clientID, clientSecret, redirectURI, username, password string, key *rsa.PrivateKey) *provider {
	provider := &provider{issuer: strings.TrimSuffix(issuer, "/"), clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI, username: username, password: password, key: key, codes: map[string]authorizationCode{}, mux: http.NewServeMux()}
	provider.mux.HandleFunc("GET /.well-known/openid-configuration", provider.discovery)
	provider.mux.HandleFunc("GET /jwks", provider.jwks)
	provider.mux.HandleFunc("GET /authorize", provider.authorize)
	provider.mux.HandleFunc("POST /authorize", provider.authorize)
	provider.mux.HandleFunc("POST /token", provider.token)
	provider.mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNoContent) })
	return provider
}

func (provider *provider) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	provider.mux.ServeHTTP(writer, request)
}

func (provider *provider) discovery(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, map[string]any{
		"issuer": provider.issuer, "authorization_endpoint": provider.issuer + "/authorize", "token_endpoint": provider.issuer + "/token", "jwks_uri": provider.issuer + "/jwks",
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported": []string{"openid", "profile", "email", "gateway.admin"}, "code_challenge_methods_supported": []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (provider *provider) jwks(writer http.ResponseWriter, _ *http.Request) {
	exponent := big.NewInt(int64(provider.key.PublicKey.E)).Bytes()
	writeJSON(writer, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "demo", "n": base64.RawURLEncoding.EncodeToString(provider.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent),
	}}})
}

func (provider *provider) authorize(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	fields := map[string]string{}
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method"} {
		fields[key] = request.Form.Get(key)
	}
	if fields["client_id"] != provider.clientID || fields["redirect_uri"] != provider.redirectURI || fields["response_type"] != "code" || fields["code_challenge_method"] != "S256" || fields["code_challenge"] == "" || !containsScope(fields["scope"], "openid") || !containsScope(fields["scope"], "gateway.admin") {
		http.Error(writer, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if request.Method == http.MethodGet {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPage.Execute(writer, map[string]any{"Fields": fields})
		return
	}
	if request.Form.Get("username") != provider.username || request.Form.Get("password") != provider.password {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_ = loginPage.Execute(writer, map[string]any{"Fields": fields, "Error": "Invalid email or password"})
		return
	}
	code, err := randomToken(32)
	if err != nil {
		http.Error(writer, "random failure", http.StatusInternalServerError)
		return
	}
	provider.mu.Lock()
	provider.codes[code] = authorizationCode{challenge: fields["code_challenge"], redirectURI: fields["redirect_uri"], scope: fields["scope"], subject: "demo-admin", expires: time.Now().Add(2 * time.Minute)}
	provider.mu.Unlock()
	redirect, _ := url.Parse(fields["redirect_uri"])
	query := redirect.Query()
	query.Set("code", code)
	query.Set("state", fields["state"])
	redirect.RawQuery = query.Encode()
	http.Redirect(writer, request, redirect.String(), http.StatusFound)
}

func (provider *provider) token(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		oauthError(writer, "invalid_request", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, basic := request.BasicAuth()
	if !basic {
		clientID, clientSecret = request.Form.Get("client_id"), request.Form.Get("client_secret")
	}
	if clientID != provider.clientID || clientSecret != provider.clientSecret {
		oauthError(writer, "invalid_client", http.StatusUnauthorized)
		return
	}
	if request.Form.Get("grant_type") != "authorization_code" {
		oauthError(writer, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	codeValue := request.Form.Get("code")
	provider.mu.Lock()
	code, ok := provider.codes[codeValue]
	delete(provider.codes, codeValue)
	provider.mu.Unlock()
	challenge := sha256.Sum256([]byte(request.Form.Get("code_verifier")))
	if !ok || time.Now().After(code.expires) || request.Form.Get("redirect_uri") != code.redirectURI || base64.RawURLEncoding.EncodeToString(challenge[:]) != code.challenge {
		oauthError(writer, "invalid_grant", http.StatusBadRequest)
		return
	}
	idToken, err := provider.sign(map[string]any{"iss": provider.issuer, "aud": provider.clientID, "sub": code.subject, "email": provider.username, "scope": code.scope, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		oauthError(writer, "server_error", http.StatusInternalServerError)
		return
	}
	accessToken, err := randomToken(32)
	if err != nil {
		oauthError(writer, "server_error", http.StatusInternalServerError)
		return
	}
	writeJSON(writer, map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": 3600, "scope": code.scope, "id_token": idToken})
}

func (provider *provider) sign(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "demo", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, provider.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func containsScope(scopes, wanted string) bool {
	for _, scope := range strings.Fields(scopes) {
		if scope == wanted {
			return true
		}
	}
	return false
}
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
func oauthError(writer http.ResponseWriter, code string, status int) {
	writer.WriteHeader(status)
	writeJSON(writer, map[string]string{"error": code})
}
