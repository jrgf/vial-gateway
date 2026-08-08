package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthorizationCodePKCE(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := newProvider("http://placeholder", "client", "secret", "http://client.example/callback", "admin@example.com", "admin", key)
	server := httptest.NewServer(provider)
	defer server.Close()
	provider.issuer = server.URL
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("v", 64)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id": {"client"}, "redirect_uri": {"http://client.example/callback"}, "response_type": {"code"},
		"scope": {"openid profile email gateway.admin"}, "state": {"state-1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		"username": {"admin@example.com"}, "password": {"admin"},
	}
	response, err := client.PostForm(server.URL+"/authorize", values)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", response.StatusCode)
	}
	redirect, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("code")
	if code == "" || redirect.Query().Get("state") != "state-1" {
		t.Fatalf("invalid redirect: %s", redirect)
	}

	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://client.example/callback"}, "code_verifier": {verifier}}
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/token", strings.NewReader(tokenForm.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("client", "secret")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", response.StatusCode)
	}
	var token struct {
		IDToken string `json:"id_token"`
		Scope   string `json:"scope"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token.IDToken, ".")
	if len(parts) != 3 || !containsScope(token.Scope, "gateway.admin") {
		t.Fatalf("invalid token response: %+v", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil || claims["iss"] != server.URL || claims["sub"] != "demo-admin" {
		t.Fatalf("invalid ID token claims: %s", payload)
	}
}
