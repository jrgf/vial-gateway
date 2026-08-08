package main

import (
	"testing"

	"github.com/jrgf/go-vial/config"
)

func TestBackendConfigurationFromEnvironment(t *testing.T) {
	configuration := backendConfig{Name: "backend"}
	if err := config.Load(&configuration, config.Environ([]string{
		"VIAL_HTTP_PORT=9002",
		"VIAL_BACKEND_NAME=orders",
	})); err != nil {
		t.Fatal(err)
	}
	if configuration.HTTP.Address() != "127.0.0.1:9002" || configuration.Name != "orders" {
		t.Fatalf("environment was not applied: %+v", configuration)
	}
}
