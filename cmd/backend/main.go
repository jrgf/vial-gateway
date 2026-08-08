package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jrgf/go-vial/config"
)

type echoedRequest struct {
	Service   string `json:"service"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	Body      string `json:"body"`
	RequestID string `json:"request_id"`
}

type backendConfig struct {
	HTTP config.HTTP `json:"http"`
	Name string      `json:"name" env:"VIAL_BACKEND_NAME"`
}

func main() {
	configuration := backendConfig{Name: "backend"}
	if err := config.Load(&configuration); err != nil {
		slog.Error("load configuration", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 1<<20)
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("X-Upstream", configuration.Name)
		_ = json.NewEncoder(writer).Encode(echoedRequest{
			Service:   configuration.Name,
			Method:    request.Method,
			Path:      request.URL.Path,
			Query:     request.URL.RawQuery,
			Body:      string(body),
			RequestID: request.Header.Get("X-Request-ID"),
		})
	})

	server := &http.Server{
		Addr:              configuration.HTTP.Address(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       time.Minute,
	}
	slog.Info("demo backend listening", "service", configuration.Name, "address", configuration.HTTP.Address())
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		slog.Error("run demo backend", "error", err)
		os.Exit(1)
	}
}
