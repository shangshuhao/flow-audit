// Package logging configures structured application loggers.
package logging

import (
	"errors"
	"log/slog"
	"os"
	"strings"
)

// New creates a structured logger from configuration values.
func New(levelValue, format string) (*slog.Logger, error) {
	var level slog.Level
	switch strings.ToLower(strings.TrimSpace(levelValue)) {
	case "debug":
		level = slog.LevelDebug
	case "", "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return nil, errors.New("log.level must be debug, info, warn or error")
	}

	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		handler = slog.NewJSONHandler(os.Stdout, options)
	case "text":
		handler = slog.NewTextHandler(os.Stdout, options)
	default:
		return nil, errors.New("log.format must be json or text")
	}

	return slog.New(handler), nil
}
