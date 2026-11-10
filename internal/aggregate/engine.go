// Package aggregate materializes Flow lifecycle records from normalized events.
package aggregate

import (
	"fmt"
	"sync"

	"flowaudit/internal/flow"
)

// Engine materializes Flow records from normalized events.
type Engine struct {
	mu     sync.Mutex
	active map[string]*flow.Flow
}

// NewEngine creates an empty Flow aggregation engine.
func NewEngine() *Engine {
	return &Engine{
		active: make(map[string]*flow.Flow),
	}
}

// Restore loads open Flow records into the active index.
func (e *Engine) Restore(flows []flow.Flow) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, item := range flows {
		if !item.Open {
			continue
		}
		if err := item.Validate(); err != nil {
			return fmt.Errorf("restore flow %q: %w", item.FlowID, err)
		}

		copyFlow := item
		e.active[activeKeyFromFlow(copyFlow)] = &copyFlow
	}

	return nil
}

// Apply updates the active Flow associated with an event.
func (e *Engine) Apply(event flow.Event) (flow.Event, flow.Flow, error) {
	if err := event.Validate(); err != nil {
		return flow.Event{}, flow.Flow{}, fmt.Errorf("validate event: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	key := activeKeyFromEvent(event)
	// A repeated event for an open tuple updates the existing Flow.
	item, found := e.active[key]
	if !found {
		item = newFlow(event)
		e.active[key] = item
	} else {
		applyEvent(item, event)
	}

	if event.EventType == flow.EventTypeDestroy {
		// Closed tuples leave the active index so a later NEW creates a new Flow.
		item.Open = false
		closedAt := event.ObservedAt.UTC()
		item.ClosedAt = &closedAt
		delete(e.active, key)
	}

	event.FlowID = item.FlowID

	return event, *item, nil
}

// ActiveCount returns the number of materialized open flows.
func (e *Engine) ActiveCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.active)
}

// newFlow creates the initial materialized state for an observed event.
func newFlow(event flow.Event) *flow.Flow {
	firstSeen := event.ObservedAt.UTC()
	// Prefer an earlier kernel timestamp when the source provides one.
	if event.StartedAt != nil && !event.StartedAt.IsZero() && event.StartedAt.Before(firstSeen) {
		firstSeen = event.StartedAt.UTC()
	}
	missingFields := append([]string(nil), event.MissingFields...)

	switch event.EventType {
	case flow.EventTypeUpdate, flow.EventTypeDestroy:
		// An orphan update or close is still useful evidence but is incomplete.
		missingFields = appendUnique(missingFields, "missing_start_event")
	}

	return &flow.Flow{
		SchemaVersion: flow.SchemaVersion,
		FlowID: flow.BuildFlowID(
			event.NodeID,
			event.Source,
			event.NetNSID,
			event.Zone,
			event.Protocol,
			event.Original,
			firstSeen,
		),
		NodeID:        event.NodeID,
		Source:        event.Source,
		NetNSID:       event.NetNSID,
		Zone:          event.Zone,
		Protocol:      event.Protocol,
		Original:      event.Original,
		Reply:         event.Reply,
		NAT:           event.NAT,
		Direction:     event.Direction,
		State:         flow.NormalizeState(event.State),
		Open:          event.EventType != flow.EventTypeDestroy,
		FirstSeenAt:   firstSeen,
		LastSeenAt:    firstSeen,
		Replied:       event.Replied,
		Assured:       event.Assured,
		Preexisting:   event.Preexisting || event.EventType == flow.EventTypeImport,
		Counters:      event.Counters,
		Attribution:   event.Attribution,
		Complete:      event.Complete,
		GapID:         event.GapID,
		MissingFields: missingFields,
	}
}

// applyEvent merges monotonic and descriptive fields from an event into a Flow.
func applyEvent(item *flow.Flow, event flow.Event) {
	observedAt := event.ObservedAt.UTC()
	if observedAt.Before(item.FirstSeenAt) {
		item.FirstSeenAt = observedAt
	}
	if event.StartedAt != nil && !event.StartedAt.IsZero() && event.StartedAt.Before(item.FirstSeenAt) {
		item.FirstSeenAt = event.StartedAt.UTC()
	}
	if observedAt.After(item.LastSeenAt) {
		item.LastSeenAt = observedAt
	}

	if event.Direction != flow.DirectionUnknown {
		item.Direction = event.Direction
	}
	if event.State != "" {
		item.State = flow.NormalizeState(event.State)
	}
	if event.Reply.IsValid() {
		item.Reply = event.Reply
	}
	if event.NAT.Detected {
		item.NAT = mergeNAT(item.NAT, event.NAT)
	}

	item.Replied = item.Replied || event.Replied
	item.Assured = item.Assured || event.Assured
	item.Preexisting = item.Preexisting || event.Preexisting

	// Counter snapshots may arrive out of order, so keep the largest known value.
	if event.Counters.Available {
		item.Counters.Available = true
		item.Counters.Original = maxCounter(item.Counters.Original, event.Counters.Original)
		item.Counters.Reply = maxCounter(item.Counters.Reply, event.Counters.Reply)
	}

	item.Attribution = mergeAttribution(item.Attribution, event.Attribution)
	item.Complete = item.Complete && event.Complete
	if event.GapID != "" {
		item.GapID = event.GapID
	}
	for _, field := range event.MissingFields {
		item.MissingFields = appendUnique(item.MissingFields, field)
	}
}

// activeKeyFromEvent builds the in-memory lookup key for an event.
func activeKeyFromEvent(event flow.Event) string {
	return flow.ActiveKey(
		event.NodeID,
		event.Source,
		event.NetNSID,
		event.Zone,
		event.Protocol,
		event.Original,
	)
}

// activeKeyFromFlow builds the in-memory lookup key for a restored Flow.
func activeKeyFromFlow(item flow.Flow) string {
	return flow.ActiveKey(
		item.NodeID,
		item.Source,
		item.NetNSID,
		item.Zone,
		item.Protocol,
		item.Original,
	)
}

// maxCounter prevents out-of-order events from decreasing known counters.
func maxCounter(left, right flow.Counter) flow.Counter {
	if right.Packets > left.Packets {
		left.Packets = right.Packets
	}
	if right.Bytes > left.Bytes {
		left.Bytes = right.Bytes
	}

	return left
}

// mergeNAT combines sticky NAT flags and optional translated tuples.
func mergeNAT(current, incoming flow.NAT) flow.NAT {
	current.Detected = current.Detected || incoming.Detected
	current.SourceNAT = current.SourceNAT || incoming.SourceNAT
	current.DestinationNAT = current.DestinationNAT || incoming.DestinationNAT
	current.SourceNATDone = current.SourceNATDone || incoming.SourceNATDone
	current.DestinationDone = current.DestinationDone || incoming.DestinationDone
	if incoming.Original != nil {
		value := *incoming.Original
		current.Original = &value
	}
	if incoming.Reply != nil {
		value := *incoming.Reply
		current.Reply = &value
	}

	return current
}

// mergeAttribution keeps the most trustworthy attribution available.
func mergeAttribution(current, incoming flow.Attribution) flow.Attribution {
	if !hasAttribution(incoming) {
		return current
	}

	if confidenceRank(incoming.Confidence) >= confidenceRank(current.Confidence) {
		return incoming
	}

	return current
}

// hasAttribution reports whether any attribution field contains evidence.
func hasAttribution(value flow.Attribution) bool {
	return value.PID != 0 ||
		value.ProcessName != "" ||
		value.UserID != "" ||
		value.UserName != "" ||
		value.ContainerID != ""
}

// confidenceRank orders attribution sources by trustworthiness.
func confidenceRank(value flow.Confidence) int {
	switch value {
	case flow.ConfidenceObserved:
		return 3
	case flow.ConfidenceInferred:
		return 2
	case flow.ConfidenceUnknown:
		return 1
	default:
		return 0
	}
}

// appendUnique adds a non-empty string without creating duplicates.
func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}

	return append(values, value)
}
