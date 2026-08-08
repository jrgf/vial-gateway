package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type dynamicDNSWorker struct {
	config      dynamicDNSConfig
	bearerToken string
	client      *http.Client
	metrics     *gatewayMetrics
	logger      *slog.Logger
	lastIP      string
}

func newDynamicDNSWorker(configuration dynamicDNSConfig, bearerToken string, metrics *gatewayMetrics, logger *slog.Logger) *dynamicDNSWorker {
	return &dynamicDNSWorker{
		config:      configuration,
		bearerToken: bearerToken,
		client:      &http.Client{Timeout: configuration.Timeout.value()},
		metrics:     metrics,
		logger:      logger,
	}
}

func (worker *dynamicDNSWorker) run(ctx context.Context) {
	ticker := time.NewTicker(worker.config.Interval.value())
	defer ticker.Stop()
	for {
		changed, err := worker.sync(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			worker.metrics.dynamicDNS.WithLabelValues("error").Inc()
			worker.logger.WarnContext(ctx, "dynamic DNS update failed", "error", err)
		} else if changed {
			worker.metrics.dynamicDNS.WithLabelValues("updated").Inc()
			worker.logger.InfoContext(ctx, "dynamic DNS record updated", "ip", worker.lastIP)
		} else {
			worker.metrics.dynamicDNS.WithLabelValues("unchanged").Inc()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (worker *dynamicDNSWorker) sync(ctx context.Context) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, worker.config.CheckURL, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Accept", "text/plain")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("User-Agent", "vial-gateway-dynamic-dns/1")
	response, err := worker.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("discover public IP: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false, fmt.Errorf("discover public IP: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 129))
	if err != nil {
		return false, fmt.Errorf("read public IP: %w", err)
	}
	if len(body) > 128 {
		return false, errors.New("public IP response is too large")
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return false, errors.New("public IP endpoint returned a non-public address")
	}
	canonical := ip.String()
	if canonical == worker.lastIP {
		return false, nil
	}

	updateURL := strings.ReplaceAll(worker.config.UpdateURL, "{ip}", url.QueryEscape(canonical))
	update, err := http.NewRequestWithContext(ctx, http.MethodGet, updateURL, nil)
	if err != nil {
		return false, err
	}
	update.Header.Set("Accept", "application/json, text/plain;q=0.9")
	update.Header.Set("User-Agent", "vial-gateway-dynamic-dns/1")
	if worker.bearerToken != "" {
		update.Header.Set("Authorization", "Bearer "+worker.bearerToken)
	}
	result, err := worker.client.Do(update)
	if err != nil {
		return false, fmt.Errorf("update dynamic DNS: %w", err)
	}
	defer func() { _ = result.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(result.Body, 4096))
	if result.StatusCode < 200 || result.StatusCode >= 300 {
		return false, fmt.Errorf("update dynamic DNS: HTTP %d", result.StatusCode)
	}
	worker.lastIP = canonical
	return true, nil
}
