package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestDynamicDNSUpdatesOnlyWhenPublicIPChanges(t *testing.T) {
	var publicIP atomic.Value
	publicIP.Store("8.8.8.8")
	check := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(publicIP.Load().(string)))
	}))
	defer check.Close()
	var updates atomic.Int32
	update := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("ip") == "" {
			t.Error("update did not contain ip")
		}
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("bearer token missing")
		}
		updates.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer update.Close()
	metrics := newGatewayMetrics()
	worker := newDynamicDNSWorker(dynamicDNSConfig{Enabled: true, CheckURL: check.URL, UpdateURL: update.URL + "?ip={ip}", Interval: duration(time.Minute), Timeout: duration(time.Second)}, "test-token", &metrics, slog.Default())

	changed, err := worker.sync(context.Background())
	if err != nil || !changed {
		t.Fatalf("first sync changed=%v err=%v", changed, err)
	}
	changed, err = worker.sync(context.Background())
	if err != nil || changed {
		t.Fatalf("unchanged sync changed=%v err=%v", changed, err)
	}
	publicIP.Store("1.1.1.1")
	changed, err = worker.sync(context.Background())
	if err != nil || !changed {
		t.Fatalf("changed sync changed=%v err=%v", changed, err)
	}
	if updates.Load() != 2 {
		t.Fatalf("updates = %d, want 2", updates.Load())
	}
}

func TestDynamicDNSRejectsNonPublicAddress(t *testing.T) {
	check := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write([]byte("192.168.1.10")) }))
	defer check.Close()
	var updates atomic.Int32
	update := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { updates.Add(1) }))
	defer update.Close()
	metrics := newGatewayMetrics()
	worker := newDynamicDNSWorker(dynamicDNSConfig{Enabled: true, CheckURL: check.URL, UpdateURL: update.URL + "?ip={ip}", Interval: duration(time.Minute), Timeout: duration(time.Second)}, "", &metrics, slog.Default())
	if _, err := worker.sync(context.Background()); err == nil {
		t.Fatal("private address was accepted")
	}
	if updates.Load() != 0 {
		t.Fatal("invalid address reached update endpoint")
	}
}
