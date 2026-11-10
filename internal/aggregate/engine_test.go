package aggregate

import (
	"net/netip"
	"testing"
	"time"

	"flowaudit/internal/flow"
)

func TestEngineBuildsFlowLifecycle(t *testing.T) {
	engine := NewEngine()
	start := time.Date(2026, time.November, 9, 1, 0, 0, 0, time.UTC)

	newEvent := testEvent("event-1", flow.EventTypeNew, start, 100, 200, false)
	updatedEvent, item, err := engine.Apply(newEvent)
	if err != nil {
		t.Fatalf("Apply(new) error = %v", err)
	}
	if updatedEvent.FlowID == "" || item.FlowID == "" {
		t.Fatal("new flow id is empty")
	}
	if !item.Open {
		t.Fatal("new flow is not open")
	}
	flowID := item.FlowID

	updateEvent := testEvent("event-2", flow.EventTypeUpdate, start.Add(time.Second), 300, 400, true)
	updateEvent.Attribution = flow.Attribution{
		PID:         42,
		ProcessName: "curl",
		Confidence:  flow.ConfidenceObserved,
	}
	_, item, err = engine.Apply(updateEvent)
	if err != nil {
		t.Fatalf("Apply(update) error = %v", err)
	}
	if item.FlowID != flowID {
		t.Fatalf("FlowID changed from %q to %q", flowID, item.FlowID)
	}
	if item.Counters.Original.Bytes != 300 || item.Counters.Reply.Bytes != 400 {
		t.Fatalf("unexpected counters: %+v", item.Counters)
	}
	if item.Attribution.ProcessName != "curl" {
		t.Fatalf("ProcessName = %q", item.Attribution.ProcessName)
	}

	closeEvent := testEvent("event-3", flow.EventTypeDestroy, start.Add(2*time.Second), 500, 600, true)
	_, item, err = engine.Apply(closeEvent)
	if err != nil {
		t.Fatalf("Apply(destroy) error = %v", err)
	}
	if item.Open {
		t.Fatal("destroyed flow is still open")
	}
	if item.ClosedAt == nil || !item.ClosedAt.Equal(start.Add(2*time.Second)) {
		t.Fatalf("ClosedAt = %v", item.ClosedAt)
	}
	if engine.ActiveCount() != 0 {
		t.Fatalf("ActiveCount = %d", engine.ActiveCount())
	}
}

func TestEngineRejectsInvalidEvent(t *testing.T) {
	engine := NewEngine()
	event := testEvent("event-1", flow.EventTypeNew, time.Now(), 1, 1, false)
	event.Original.SourceIP = netip.Addr{}

	if _, _, err := engine.Apply(event); err == nil {
		t.Fatal("Apply() expected an error")
	}
}

func testEvent(
	eventID string,
	eventType flow.EventType,
	at time.Time,
	originalBytes uint64,
	replyBytes uint64,
	replied bool,
) flow.Event {
	return flow.Event{
		SchemaVersion: flow.SchemaVersion,
		EventID:       eventID,
		NodeID:        "node-1",
		Source:        "conntrack",
		EventType:     eventType,
		ObservedAt:    at,
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
		Direction: flow.DirectionOutbound,
		State:     "ESTABLISHED",
		Replied:   replied,
		Counters: flow.Counters{
			Available: true,
			Original: flow.Counter{
				Packets: originalBytes / 10,
				Bytes:   originalBytes,
			},
			Reply: flow.Counter{
				Packets: replyBytes / 10,
				Bytes:   replyBytes,
			},
		},
		Attribution: flow.Attribution{Confidence: flow.ConfidenceUnknown},
		Complete:    true,
	}
}
