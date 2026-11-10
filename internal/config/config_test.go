package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Store.Type != "sqlite" {
		t.Fatalf("Store.Type = %q", cfg.Store.Type)
	}
	if cfg.Store.FlushInterval.Std() != time.Second {
		t.Fatalf("FlushInterval = %s", cfg.Store.FlushInterval.Std())
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte(`
source:
  queue_size: 16
store:
  path: custom.db
  flush_interval: 2s
http:
  listen: 127.0.0.1:9090
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Source.QueueSize != 16 {
		t.Fatalf("QueueSize = %d", cfg.Source.QueueSize)
	}
	if cfg.Store.Path != "custom.db" {
		t.Fatalf("Store.Path = %q", cfg.Store.Path)
	}
	if cfg.Store.FlushInterval.Std() != 2*time.Second {
		t.Fatalf("FlushInterval = %s", cfg.Store.FlushInterval.Std())
	}
}
