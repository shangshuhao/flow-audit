package sqlite

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"flowaudit/internal/flow"
	"flowaudit/internal/store"
)

func TestStoreFlowLifecycleAndQuery(t *testing.T) {
	ctx := context.Background()
	storage, err := Open(ctx, filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	now := time.Date(2026, time.November, 9, 2, 0, 0, 0, time.UTC)
	event := testFlowEvent(now)
	item := testFlow(now)
	event.FlowID = item.FlowID

	if err := storage.ApplyBatch(ctx, []store.Record{{Event: event, Flow: item}}); err != nil {
		t.Fatalf("ApplyBatch() error = %v", err)
	}

	got, err := storage.GetFlow(ctx, item.FlowID)
	if err != nil {
		t.Fatalf("GetFlow() error = %v", err)
	}
	if got.Original.DestinationPort != 443 {
		t.Fatalf("DestinationPort = %d", got.Original.DestinationPort)
	}

	limit := 10
	query := flow.Query{
		Start: &now,
		End:   timePointer(now.Add(time.Minute)),
		IP:    addrPointer(netip.MustParseAddr("1.1.1.1")),
		Limit: limit,
	}
	page, err := storage.QueryFlows(ctx, query)
	if err != nil {
		t.Fatalf("QueryFlows() error = %v", err)
	}
	if len(page.Items) != 1 || page.Summary.Count != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}

	events, err := storage.ListFlowEvents(ctx, item.FlowID)
	if err != nil {
		t.Fatalf("ListFlowEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].EventID != event.EventID {
		t.Fatalf("unexpected events: %+v", events)
	}

	restored, err := storage.RestoreOpenFlows(ctx)
	if err != nil {
		t.Fatalf("RestoreOpenFlows() error = %v", err)
	}
	if len(restored) != 1 || restored[0].FlowID != item.FlowID {
		t.Fatalf("unexpected restored flows: %+v", restored)
	}
}

func TestStoreCaptureGap(t *testing.T) {
	ctx := context.Background()
	storage, err := Open(ctx, filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	now := time.Now().UTC()
	gap := flow.CaptureGap{
		GapID:     "gap-1",
		NodeID:    "node-1",
		Source:    "conntrack",
		StartedAt: now,
		EndedAt:   &now,
		Reason:    flow.GapReasonNetlinkENOBUFS,
		LostCount: 3,
	}
	if err := storage.AppendGap(ctx, gap); err != nil {
		t.Fatalf("AppendGap() error = %v", err)
	}

	items, err := storage.QueryGaps(ctx, now.Add(-time.Minute), now.Add(time.Minute))
	if err != nil {
		t.Fatalf("QueryGaps() error = %v", err)
	}
	if len(items) != 1 || items[0].LostCount != 3 {
		t.Fatalf("unexpected gaps: %+v", items)
	}
}

func TestStoreRetention(t *testing.T) {
	ctx := context.Background()
	storage, err := Open(ctx, filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	now := time.Now().UTC()
	event := testFlowEvent(now)
	item := testFlow(now)
	item.Open = false
	closedAt := now
	item.ClosedAt = &closedAt
	event.EventType = flow.EventTypeDestroy
	event.FlowID = item.FlowID

	if err := storage.ApplyBatch(ctx, []store.Record{{Event: event, Flow: item}}); err != nil {
		t.Fatalf("ApplyBatch() error = %v", err)
	}
	if err := storage.DeleteBefore(ctx, now.Add(time.Second), now.Add(time.Second)); err != nil {
		t.Fatalf("DeleteBefore() error = %v", err)
	}
	page, err := storage.QueryFlows(ctx, flow.Query{Limit: 10})
	if err != nil {
		t.Fatalf("QueryFlows() error = %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("retention left %d flows", len(page.Items))
	}
}

func testFlowEvent(now time.Time) flow.Event {
	return flow.Event{
		SchemaVersion: flow.SchemaVersion,
		EventID:       "event-1",
		NodeID:        "node-1",
		Source:        "conntrack",
		EventType:     flow.EventTypeNew,
		ObservedAt:    now,
		Protocol:      flow.ProtocolTCP,
		Original: flow.Tuple{
			SourceIP:        netip.MustParseAddr("10.0.0.10"),
			SourcePort:      52344,
			DestinationIP:   netip.MustParseAddr("1.1.1.1"),
			DestinationPort: 443,
		},
		Reply: flow.Tuple{
			SourceIP:        netip.MustParseAddr("1.1.1.1"),
			SourcePort:      443,
			DestinationIP:   netip.MustParseAddr("10.0.0.10"),
			DestinationPort: 52344,
		},
		Direction:   flow.DirectionOutbound,
		State:       "ESTABLISHED",
		Counters:    flow.Counters{Available: true, Original: flow.Counter{Bytes: 100}, Reply: flow.Counter{Bytes: 200}},
		Attribution: flow.Attribution{Confidence: flow.ConfidenceUnknown},
		Complete:    true,
	}
}

func testFlow(now time.Time) flow.Flow {
	return flow.Flow{
		SchemaVersion: flow.SchemaVersion,
		FlowID:        "flow-1",
		NodeID:        "node-1",
		Source:        "conntrack",
		Protocol:      flow.ProtocolTCP,
		Original: flow.Tuple{
			SourceIP:        netip.MustParseAddr("10.0.0.10"),
			SourcePort:      52344,
			DestinationIP:   netip.MustParseAddr("1.1.1.1"),
			DestinationPort: 443,
		},
		Reply: flow.Tuple{
			SourceIP:        netip.MustParseAddr("1.1.1.1"),
			SourcePort:      443,
			DestinationIP:   netip.MustParseAddr("10.0.0.10"),
			DestinationPort: 52344,
		},
		Direction:   flow.DirectionOutbound,
		State:       "ESTABLISHED",
		Open:        true,
		FirstSeenAt: now,
		LastSeenAt:  now,
		Counters:    flow.Counters{Available: true, Original: flow.Counter{Bytes: 100}, Reply: flow.Counter{Bytes: 200}},
		Attribution: flow.Attribution{Confidence: flow.ConfidenceUnknown},
		Complete:    true,
	}
}

func timePointer(value time.Time) *time.Time {
	return &value
}

func addrPointer(value netip.Addr) *netip.Addr {
	return &value
}
