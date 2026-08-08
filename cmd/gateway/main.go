package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jrgf/go-vial/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type certificateReloader struct {
	current atomic.Pointer[tls.Certificate]
}

func loadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &certificate, nil
}

func (reloader *certificateReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certificate := reloader.current.Load()
	if certificate == nil {
		return nil, errors.New("TLS certificate is not loaded")
	}
	return certificate, nil
}

func reloadGateway(app *gatewayApp, certificates *certificateReloader, replacement applicationConfig) error {
	if err := replacement.Validate(); err != nil {
		return err
	}
	tlsEnabled := replacement.TLS.CertFile != ""
	if tlsEnabled != (certificates != nil) {
		return errors.New("TLS listener mode cannot change during reload")
	}
	var certificate *tls.Certificate
	if tlsEnabled {
		var err error
		certificate, err = loadCertificate(replacement.TLS.CertFile, replacement.TLS.KeyFile)
		if err != nil {
			return err
		}
	}
	if err := app.manager.Activate(replacement.Gateway); err != nil {
		return err
	}
	if certificate != nil {
		certificates.current.Store(certificate)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.json", "optional JSON configuration file")
	flag.Parse()

	configuration := defaultConfig()
	if err := config.Load(&configuration, config.OptionalFile(*configPath)); err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if err := configuration.Validate(); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}
	shutdownTelemetry, err := configureTelemetry(context.Background(), configuration.Gateway.Telemetry)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTelemetry(ctx); err != nil {
			slog.Warn("shutdown telemetry", "error", err)
		}
	}()

	app, err := newApp(configuration)
	if err != nil {
		return fmt.Errorf("configure gateway: %w", err)
	}
	defer func() {
		if err := app.Close(); err != nil {
			slog.Warn("close gateway", "error", err)
		}
	}()

	listener, err := net.Listen("tcp", configuration.HTTP.Address())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = listener.Close() }()
	var certificates *certificateReloader
	if configuration.TLS.CertFile != "" {
		certificates = &certificateReloader{}
		certificate, err := loadCertificate(configuration.TLS.CertFile, configuration.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		certificates.current.Store(certificate)
		listener = tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certificates.get})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.Start(ctx)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	go func() {
		for received := range signals {
			if received != syscall.SIGHUP {
				cancel()
				return
			}
			replacement := defaultConfig()
			if err := config.Load(&replacement, config.OptionalFile(*configPath)); err != nil {
				slog.Error("reload configuration", "error", err)
				continue
			}
			if err := reloadGateway(app, certificates, replacement); err != nil {
				slog.Error("reject configuration reload", "error", err)
				continue
			}
		}
	}()
	if err := app.Serve(ctx, listener); err != nil && ctx.Err() == nil {
		return fmt.Errorf("run gateway: %w", err)
	}
	return nil
}

func configureTelemetry(ctx context.Context, configuration telemetryConfig) (func(context.Context) error, error) {
	if configuration.OTLPEndpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(configuration.OTLPEndpoint))
	if err != nil {
		return nil, err
	}
	service := configuration.ServiceName
	if service == "" {
		service = "vial-gateway"
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(time.Second)),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", service))),
	)
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}
