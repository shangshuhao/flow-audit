// Package config loads, defaults, and validates application configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a YAML-friendly time.Duration.
type Duration time.Duration

// UnmarshalYAML parses standard Go duration strings.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var value string
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("decode duration: %w", err)
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value, err)
	}
	*d = Duration(parsed)

	return nil
}

// Std returns the standard library duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// Config contains the complete runtime configuration.
type Config struct {
	Node    NodeConfig    `yaml:"node"`
	Source  SourceConfig  `yaml:"source"`
	Store   StoreConfig   `yaml:"store"`
	HTTP    HTTPConfig    `yaml:"http"`
	Log     LogConfig     `yaml:"log"`
	Metrics MetricsConfig `yaml:"metrics"`
}

// NodeConfig identifies the audit node that emits Flow events.
type NodeConfig struct {
	ID string `yaml:"id"`
}

// SourceConfig controls telemetry collection and buffering.
type SourceConfig struct {
	Type                 string   `yaml:"type"`
	IncludePreexisting   bool     `yaml:"include_preexisting"`
	IncludeUnreplied     bool     `yaml:"include_unreplied"`
	QueueSize            int      `yaml:"queue_size"`
	NetlinkReceiveBuffer int      `yaml:"netlink_receive_buffer"`
	ReconnectBackoff     Duration `yaml:"reconnect_backoff"`
}

// StoreConfig controls persistence, batching, and retention.
type StoreConfig struct {
	Type           string   `yaml:"type"`
	Path           string   `yaml:"path"`
	BatchSize      int      `yaml:"batch_size"`
	FlushInterval  Duration `yaml:"flush_interval"`
	EventRetention Duration `yaml:"event_retention"`
	FlowRetention  Duration `yaml:"flow_retention"`
}

// HTTPConfig controls the read-only API listener and authentication.
type HTTPConfig struct {
	Listen    string `yaml:"listen"`
	AuthToken string `yaml:"auth_token"`
}

// LogConfig controls structured application logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig controls Prometheus-format metric exposure.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Default returns the development defaults.
func Default() Config {
	return Config{
		Node: NodeConfig{ID: "auto"},
		Source: SourceConfig{
			Type:               "conntrack",
			IncludePreexisting: true,
			IncludeUnreplied:   true,
			QueueSize:          4096,
			ReconnectBackoff:   Duration(3 * time.Second),
		},
		Store: StoreConfig{
			Type:           "sqlite",
			Path:           filepath.Join("data", "flows.db"),
			BatchSize:      128,
			FlushInterval:  Duration(time.Second),
			EventRetention: Duration(7 * 24 * time.Hour),
			FlowRetention:  Duration(90 * 24 * time.Hour),
		},
		HTTP:    HTTPConfig{Listen: "127.0.0.1:8080"},
		Log:     LogConfig{Level: "info", Format: "json"},
		Metrics: MetricsConfig{Enabled: true},
	}
}

// Load reads a YAML configuration file. An empty path returns defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		if err := cfg.normalize(); err != nil {
			return Config{}, err
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := cfg.normalize(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// normalize applies defaults and rejects unsafe or incomplete settings.
func (c *Config) normalize() error {
	if c.Source.Type == "" {
		c.Source.Type = "conntrack"
	}
	if c.Source.QueueSize <= 0 {
		return errors.New("source.queue_size must be greater than zero")
	}
	if c.Source.ReconnectBackoff <= 0 {
		return errors.New("source.reconnect_backoff must be greater than zero")
	}
	if c.Store.Type == "" {
		c.Store.Type = "sqlite"
	}
	if c.Store.Path == "" {
		return errors.New("store.path is required")
	}
	if c.Store.BatchSize <= 0 {
		return errors.New("store.batch_size must be greater than zero")
	}
	if c.Store.FlushInterval <= 0 {
		return errors.New("store.flush_interval must be greater than zero")
	}
	if c.Store.EventRetention <= 0 {
		return errors.New("store.event_retention must be greater than zero")
	}
	if c.Store.FlowRetention <= 0 {
		return errors.New("store.flow_retention must be greater than zero")
	}
	if strings.TrimSpace(c.HTTP.Listen) == "" {
		return errors.New("http.listen is required")
	}

	if c.Node.ID == "" {
		c.Node.ID = "auto"
	}
	if c.Node.ID == "auto" {
		nodeID, err := detectNodeID()
		if err != nil {
			return err
		}
		c.Node.ID = nodeID
	}
	if strings.TrimSpace(c.Node.ID) == "" {
		return errors.New("node.id is empty")
	}

	return nil
}

// detectNodeID derives a stable node identifier from machine identity data.
func detectNodeID() (string, error) {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err == nil && strings.TrimSpace(string(machineID)) != "" {
		sum := sha256.Sum256([]byte(strings.TrimSpace(string(machineID))))
		return hex.EncodeToString(sum[:8]), nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("detect node id: %w", err)
	}
	sum := sha256.Sum256([]byte(strings.ToLower(hostname)))

	return hex.EncodeToString(sum[:8]), nil
}
