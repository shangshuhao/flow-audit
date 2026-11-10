// Package runtime assembles collection, storage, and HTTP components.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"flowaudit/internal/app/agent"
	"flowaudit/internal/config"
	"flowaudit/internal/health"
	"flowaudit/internal/httpapi"
	"flowaudit/internal/source"
	"flowaudit/internal/store"
	"flowaudit/internal/store/sqlite"
	"flowaudit/internal/telemetry"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpIdleTimeout       = 60 * time.Second
	httpShutdownTimeout   = 10 * time.Second
)

// RunAll starts collection, storage and HTTP serving in one process.
func RunAll(
	ctx context.Context,
	cfg config.Config,
	sourceImpl source.Source,
	logger *slog.Logger,
) error {
	return run(ctx, cfg, sourceImpl, logger, true)
}

// RunServe starts the read-only HTTP server without collecting events.
func RunServe(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
) error {
	return run(ctx, cfg, nil, logger, false)
}

// run assembles storage, HTTP serving, and optional collection.
func run(
	ctx context.Context,
	cfg config.Config,
	sourceImpl source.Source,
	logger *slog.Logger,
	collect bool,
) error {
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()

	storage, err := openStore(runContext, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := storage.Close(); err != nil {
			logger.Error("close store failed", "error", err)
		}
	}()

	status := health.New()
	status.SetStore(health.StateHealthy, nil)
	metrics := telemetry.New()

	api, err := httpapi.New(
		storage,
		status,
		metrics,
		logger,
		cfg.HTTP.AuthToken,
		cfg.Metrics.Enabled,
	)
	if err != nil {
		return fmt.Errorf("create HTTP API: %w", err)
	}

	listener, err := net.Listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTP.Listen, err)
	}

	// Bind before starting the server so listener errors fail fast.
	httpServer := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
	}
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("HTTP server started", "address", listener.Addr().String())
		err := httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
			return
		}
		serverErrors <- nil
	}()

	agentErrors := make(chan error, 1)
	if collect {
		if sourceImpl == nil {
			return errors.New("source is required in collection mode")
		}

		collector, err := agent.New(
			sourceImpl,
			storage,
			status,
			metrics,
			logger.With("component", "agent"),
			agent.Options{
				NodeID:           cfg.Node.ID,
				EventQueueSize:   cfg.Source.QueueSize,
				BatchSize:        cfg.Store.BatchSize,
				FlushInterval:    cfg.Store.FlushInterval.Std(),
				ReconnectBackoff: cfg.Source.ReconnectBackoff.Std(),
				EventRetention:   cfg.Store.EventRetention.Std(),
				FlowRetention:    cfg.Store.FlowRetention.Std(),
			},
		)
		if err != nil {
			return fmt.Errorf("create agent: %w", err)
		}

		go func() {
			agentErrors <- collector.Run(runContext)
		}()
	} else {
		status.SetSource(health.StateStopped, nil)
	}

	var result error
	// The runtime exits when the caller cancels, serving fails, or collection fails.
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if err != nil {
			result = fmt.Errorf("HTTP server failed: %w", err)
		}
	case err := <-agentErrors:
		if err != nil {
			status.SetSource(health.StateFailed, err)
			result = fmt.Errorf("agent failed: %w", err)
		}
	}

	cancel()
	status.SetSource(health.StateStopped, nil)

	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shutdown HTTP server: %w", err)
	}
	status.SetStore(health.StateStopped, nil)

	return result
}

// openStore selects and opens the configured persistence backend.
func openStore(ctx context.Context, cfg config.Config) (store.Store, error) {
	switch cfg.Store.Type {
	case "sqlite":
		storage, err := sqlite.Open(ctx, cfg.Store.Path)
		if err != nil {
			return nil, fmt.Errorf("open sqlite store: %w", err)
		}
		return storage, nil
	default:
		return nil, fmt.Errorf("unsupported store type %q", cfg.Store.Type)
	}
}
