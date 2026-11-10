package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"flowaudit/internal/flow"
	"flowaudit/internal/store"
)

// ApplyBatch persists events and Flow snapshots in one transaction.
func (s *Store) ApplyBatch(ctx context.Context, records []store.Record) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin store batch: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, record := range records {
		if err := record.Event.Validate(); err != nil {
			return fmt.Errorf("validate event %q: %w", record.Event.EventID, err)
		}
		if err := record.Flow.Validate(); err != nil {
			return fmt.Errorf("validate flow %q: %w", record.Flow.FlowID, err)
		}

		if err := insertEvent(ctx, tx, record.Event); err != nil {
			return err
		}
		if err := upsertFlow(ctx, tx, record.Flow); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit store batch: %w", err)
	}

	return nil
}

// insertEvent persists the normalized event as immutable JSON history.
func insertEvent(ctx context.Context, tx *sql.Tx, event flow.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode event %q: %w", event.EventID, err)
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO flow_events(
    event_id, flow_id, node_id, source, event_type, observed_at_ns, payload_json
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO NOTHING`,
		event.EventID,
		event.FlowID,
		event.NodeID,
		event.Source,
		event.EventType,
		event.ObservedAt.UTC().UnixNano(),
		string(payload),
	)
	if err != nil {
		return fmt.Errorf("insert event %q: %w", event.EventID, err)
	}

	return nil
}

// upsertFlow updates indexed summary columns and the complete Flow payload.
func upsertFlow(ctx context.Context, tx *sql.Tx, item flow.Flow) error {
	payload, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode flow %q: %w", item.FlowID, err)
	}

	var closedAt any
	if item.ClosedAt != nil {
		closedAt = item.ClosedAt.UTC().UnixNano()
	}

	// Keep query columns indexed while payload_json remains the authoritative snapshot.
	_, err = tx.ExecContext(ctx, `
INSERT INTO flows(
    flow_id, node_id, source, netns_id, zone, protocol,
    original_src_ip, original_src_port, original_dst_ip, original_dst_port,
    reply_src_ip, reply_src_port, reply_dst_ip, reply_dst_port,
    direction, state, open, first_seen_ns, last_seen_ns, closed_at_ns,
    original_bytes, reply_bytes, complete, payload_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(flow_id) DO UPDATE SET
    netns_id = excluded.netns_id,
    zone = excluded.zone,
    protocol = excluded.protocol,
    original_src_ip = excluded.original_src_ip,
    original_src_port = excluded.original_src_port,
    original_dst_ip = excluded.original_dst_ip,
    original_dst_port = excluded.original_dst_port,
    reply_src_ip = excluded.reply_src_ip,
    reply_src_port = excluded.reply_src_port,
    reply_dst_ip = excluded.reply_dst_ip,
    reply_dst_port = excluded.reply_dst_port,
    direction = excluded.direction,
    state = excluded.state,
    open = excluded.open,
    first_seen_ns = MIN(flows.first_seen_ns, excluded.first_seen_ns),
    last_seen_ns = MAX(flows.last_seen_ns, excluded.last_seen_ns),
    closed_at_ns = excluded.closed_at_ns,
    original_bytes = MAX(flows.original_bytes, excluded.original_bytes),
    reply_bytes = MAX(flows.reply_bytes, excluded.reply_bytes),
    complete = MIN(flows.complete, excluded.complete),
    payload_json = excluded.payload_json`,
		item.FlowID,
		item.NodeID,
		item.Source,
		item.NetNSID,
		item.Zone,
		item.Protocol,
		item.Original.SourceIP.String(),
		item.Original.SourcePort,
		item.Original.DestinationIP.String(),
		item.Original.DestinationPort,
		nullableIP(item.Reply.SourceIP),
		nullablePort(item.Reply.SourceIP.IsValid(), item.Reply.SourcePort),
		nullableIP(item.Reply.DestinationIP),
		nullablePort(item.Reply.DestinationIP.IsValid(), item.Reply.DestinationPort),
		item.Direction,
		nullableString(item.State),
		boolInt(item.Open),
		item.FirstSeenAt.UTC().UnixNano(),
		item.LastSeenAt.UTC().UnixNano(),
		closedAt,
		item.Counters.Original.Bytes,
		item.Counters.Reply.Bytes,
		boolInt(item.Complete),
		string(payload),
	)
	if err != nil {
		return fmt.Errorf("upsert flow %q: %w", item.FlowID, err)
	}

	return nil
}
