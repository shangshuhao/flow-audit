// Package agent coordinates event collection, aggregation, and persistence.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"flowaudit/internal/aggregate"
	"flowaudit/internal/flow"
	"flowaudit/internal/health"
	"flowaudit/internal/source"
	"flowaudit/internal/store"
	"flowaudit/internal/telemetry"
)

const (
	retentionCheckInterval = time.Hour
	retentionWriteTimeout  = 30 * time.Second
)

// Options configures the collection agent.
type Options struct {
	NodeID           string
	EventQueueSize   int
	BatchSize        int
	FlushInterval    time.Duration
	ReconnectBackoff time.Duration
	EventRetention   time.Duration
	FlowRetention    time.Duration
}

// Agent owns the collection, aggregation and persistence pipeline.
type Agent struct {
	source  source.Source
	store   store.Store
	status  *health.Status
	metrics *telemetry.Metrics
	logger  *slog.Logger
	options Options
}

// New creates a collection agent.
func New(
	sourceImpl source.Source,
	storage store.Store,
	status *health.Status,
	metrics *telemetry.Metrics,
	logger *slog.Logger,
	options Options,
) (*Agent, error) {
	if sourceImpl == nil {
		return nil, errors.New("source is required")
	}
	if storage == nil {
		return nil, errors.New("store is required")
	}
	if status == nil {
		return nil, errors.New("status is required")
	}
	if metrics == nil {
		return nil, errors.New("metrics is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if options.NodeID == "" {
		return nil, errors.New("node id is required")
	}
	if options.BatchSize <= 0 {
		return nil, errors.New("batch size must be greater than zero")
	}
	if options.EventQueueSize <= 0 {
		return nil, errors.New("event queue size must be greater than zero")
	}
	if options.FlushInterval <= 0 {
		return nil, errors.New("flush interval must be greater than zero")
	}
	if options.ReconnectBackoff <= 0 {
		return nil, errors.New("reconnect backoff must be greater than zero")
	}

	return &Agent{
		source:  sourceImpl,
		store:   storage,
		status:  status,
		metrics: metrics,
		logger:  logger,
		options: options,
	}, nil
}

// Run processes source events until the context is canceled.
func (a *Agent) Run(ctx context.Context) error {
	engine := aggregate.NewEngine()
	// Restore active flows so a restart does not split live connections.
	existing, err := a.store.RestoreOpenFlows(ctx)
	if err != nil {
		return fmt.Errorf("restore open flows: %w", err)
	}
	if err := engine.Restore(existing); err != nil {
		return fmt.Errorf("restore aggregation state: %w", err)
	}
	a.status.ActiveFlows(int64(engine.ActiveCount()))
	a.metrics.ActiveFlows.Store(int64(engine.ActiveCount()))
	a.cleanupRetention()

	events := make(chan flow.Event, a.options.EventQueueSize)
	sourceErrors := make(chan error, 1)

	go func() {
		err := a.source.Run(ctx, events)
		if err != nil && !errors.Is(err, context.Canceled) {
			sourceErrors <- err
			return
		}
		sourceErrors <- nil
	}()
	a.status.SetSource(health.StateHealthy, nil)

	ticker := time.NewTicker(a.options.FlushInterval)
	defer ticker.Stop()
	retentionTicker := time.NewTicker(retentionCheckInterval)
	defer retentionTicker.Stop()

	batch := make([]store.Record, 0, a.options.BatchSize)
	hadEvent := false
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}

		// Final flushes must still work after the parent context is canceled.
		writeContext, cancelWrite := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelWrite()

		if err := a.store.ApplyBatch(writeContext, batch); err != nil {
			a.metrics.StoreWriteErrors.Add(1)
			a.status.SetStore(health.StateDegraded, err)
			return fmt.Errorf("write flow batch: %w", err)
		}

		a.metrics.FlowsWritten.Add(uint64(len(batch)))
		a.metrics.ActiveFlows.Store(int64(engine.ActiveCount()))
		a.status.ActiveFlows(int64(engine.ActiveCount()))
		a.status.SetStore(health.StateHealthy, nil)
		batch = batch[:0]

		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return flush()
		case err := <-sourceErrors:
			if err == nil {
				if ctx.Err() != nil {
					return flush()
				}
				err = errors.New("source stopped")
			}

			a.status.SetSource(health.StateDegraded, err)
			if strings.Contains(strings.ToLower(err.Error()), "enobufs") {
				a.metrics.NetlinkENOBUFS.Add(1)
			}
			if persistErr := a.recordGap(ctx, flow.GapReasonSourceDisconnected, err); persistErr != nil {
				return fmt.Errorf("record source failure: %w", persistErr)
			}
			if !hadEvent {
				return fmt.Errorf("source failed before producing events: %w", err)
			}

			a.logger.Warn("source disconnected; reconnecting", "error", err)
			retryTimer := time.NewTimer(a.options.ReconnectBackoff)
			select {
			case <-ctx.Done():
				if !retryTimer.Stop() {
					<-retryTimer.C
				}
				return flush()
			case <-retryTimer.C:
			}

			go func() {
				runErr := a.source.Run(ctx, events)
				if runErr != nil && !errors.Is(runErr, context.Canceled) {
					sourceErrors <- runErr
					return
				}
				sourceErrors <- nil
			}()
			a.status.SetSource(health.StateHealthy, nil)
		case event := <-events:
			hadEvent = true
			a.metrics.ObserveEvent(string(event.EventType), true)
			a.metrics.LastQueueDepth.Store(int64(len(events)))

			updatedEvent, item, err := engine.Apply(event)
			if err != nil {
				a.metrics.ParseErrors.Add(1)
				a.metrics.Drop(flow.GapReasonParseFailure, 1)
				a.logger.Warn("event rejected", "error", err, "event_id", event.EventID)
				continue
			}

			batch = append(batch, store.Record{Event: updatedEvent, Flow: item})
			a.status.EventObserved(updatedEvent.ObservedAt, int64(engine.ActiveCount()))
			a.metrics.ActiveFlows.Store(int64(engine.ActiveCount()))

			if len(batch) >= a.options.BatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := flush(); err != nil {
				return err
			}
		case <-retentionTicker.C:
			a.cleanupRetention()
		}
	}
}

// cleanupRetention removes expired events and closed flows independently.
func (a *Agent) cleanupRetention() {
	retentionContext, cancelRetention := context.WithTimeout(
		context.Background(),
		retentionWriteTimeout,
	)
	defer cancelRetention()

	now := time.Now().UTC()
	err := a.store.DeleteBefore(
		retentionContext,
		now.Add(-a.options.EventRetention),
		now.Add(-a.options.FlowRetention),
	)
	if err != nil {
		a.logger.Warn("retention cleanup failed", "error", err)
	}
}

// recordGap persists an explicit observation gap for audit completeness.
func (a *Agent) recordGap(ctx context.Context, reason string, sourceErr error) error {
	gapID, err := flow.NewEventID()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	gap := flow.CaptureGap{
		GapID:     gapID,
		NodeID:    a.options.NodeID,
		Source:    a.source.Name(),
		StartedAt: now,
		EndedAt:   &now,
		Reason:    reason,
		Details:   sourceErr.Error(),
	}
	if err := a.store.AppendGap(ctx, gap); err != nil {
		return err
	}
	a.metrics.CaptureGaps.Add(1)

	return nil
}
