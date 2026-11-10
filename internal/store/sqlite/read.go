package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"flowaudit/internal/flow"
	"flowaudit/internal/store"
)

// RestoreOpenFlows loads all active Flow snapshots.
func (s *Store) RestoreOpenFlows(ctx context.Context) ([]flow.Flow, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT payload_json FROM flows WHERE open = 1")
	if err != nil {
		return nil, fmt.Errorf("query open flows: %w", err)
	}
	defer rows.Close()

	items := make([]flow.Flow, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan open flow: %w", err)
		}
		var item flow.Flow
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, fmt.Errorf("decode open flow: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate open flows: %w", err)
	}

	return items, nil
}

// GetFlow returns a Flow by identifier.
func (s *Store) GetFlow(ctx context.Context, flowID string) (flow.Flow, error) {
	if strings.TrimSpace(flowID) == "" {
		return flow.Flow{}, errors.New("flow_id is required")
	}

	var payload string
	err := s.db.QueryRowContext(
		ctx,
		"SELECT payload_json FROM flows WHERE flow_id = ?",
		flowID,
	).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return flow.Flow{}, fmt.Errorf("flow %q: %w", flowID, store.ErrNotFound)
	}
	if err != nil {
		return flow.Flow{}, fmt.Errorf("query flow %q: %w", flowID, err)
	}

	var item flow.Flow
	if err := json.Unmarshal([]byte(payload), &item); err != nil {
		return flow.Flow{}, fmt.Errorf("decode flow %q: %w", flowID, err)
	}

	return item, nil
}

// ListFlowEvents returns the ordered lifecycle events for a Flow.
func (s *Store) ListFlowEvents(ctx context.Context, flowID string) ([]flow.Event, error) {
	if strings.TrimSpace(flowID) == "" {
		return nil, errors.New("flow_id is required")
	}

	rows, err := s.db.QueryContext(
		ctx,
		"SELECT payload_json FROM flow_events WHERE flow_id = ? ORDER BY observed_at_ns ASC, event_id ASC",
		flowID,
	)
	if err != nil {
		return nil, fmt.Errorf("query flow events %q: %w", flowID, err)
	}
	defer rows.Close()

	items := make([]flow.Event, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan flow event: %w", err)
		}
		var item flow.Event
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, fmt.Errorf("decode flow event: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate flow events: %w", err)
	}

	return items, nil
}
