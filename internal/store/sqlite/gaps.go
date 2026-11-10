package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"flowaudit/internal/flow"
)

// AppendGap stores observation completeness metadata.
func (s *Store) AppendGap(ctx context.Context, gap flow.CaptureGap) error {
	if gap.GapID == "" {
		return errors.New("gap_id is required")
	}
	if gap.NodeID == "" || gap.Source == "" || gap.Reason == "" {
		return errors.New("gap node_id, source and reason are required")
	}

	payload, err := json.Marshal(gap)
	if err != nil {
		return fmt.Errorf("encode capture gap: %w", err)
	}
	var endedAt any
	if gap.EndedAt != nil {
		endedAt = gap.EndedAt.UTC().UnixNano()
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO capture_gaps(
    gap_id, node_id, source, started_at_ns, ended_at_ns, reason, lost_count, payload_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(gap_id) DO UPDATE SET
    ended_at_ns = excluded.ended_at_ns,
    lost_count = MAX(capture_gaps.lost_count, excluded.lost_count),
    payload_json = excluded.payload_json`,
		gap.GapID,
		gap.NodeID,
		gap.Source,
		gap.StartedAt.UTC().UnixNano(),
		endedAt,
		gap.Reason,
		gap.LostCount,
		string(payload),
	)
	if err != nil {
		return fmt.Errorf("append capture gap: %w", err)
	}

	return nil
}

// QueryGaps returns capture gaps overlapping the time range.
func (s *Store) QueryGaps(ctx context.Context, start, end time.Time) ([]flow.CaptureGap, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT payload_json
FROM capture_gaps
WHERE started_at_ns <= ?
  AND (ended_at_ns IS NULL OR ended_at_ns >= ?)
ORDER BY started_at_ns DESC`,
		end.UTC().UnixNano(),
		start.UTC().UnixNano(),
	)
	if err != nil {
		return nil, fmt.Errorf("query capture gaps: %w", err)
	}
	defer rows.Close()

	items := make([]flow.CaptureGap, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan capture gap: %w", err)
		}
		var item flow.CaptureGap
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, fmt.Errorf("decode capture gap: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate capture gaps: %w", err)
	}

	return items, nil
}

// DeleteBefore applies event and flow retention independently.
func (s *Store) DeleteBefore(ctx context.Context, eventBefore, flowBefore time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin retention transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(
		ctx,
		"DELETE FROM flow_events WHERE observed_at_ns < ?",
		eventBefore.UTC().UnixNano(),
	); err != nil {
		return fmt.Errorf("delete old events: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		"DELETE FROM flows WHERE open = 0 AND last_seen_ns < ?",
		flowBefore.UTC().UnixNano(),
	); err != nil {
		return fmt.Errorf("delete old flows: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit retention transaction: %w", err)
	}

	return nil
}
