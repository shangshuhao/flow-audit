// Package flow defines source-independent connection event and Flow models.
package flow

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Tuple is the normalized network tuple in one direction.
type Tuple struct {
	SourceIP        netip.Addr `json:"source_ip"`
	SourcePort      uint16     `json:"source_port"`
	DestinationIP   netip.Addr `json:"destination_ip"`
	DestinationPort uint16     `json:"destination_port"`
}

// IsValid reports whether both addresses are valid and share an address family.
func (t Tuple) IsValid() bool {
	return t.SourceIP.IsValid() &&
		t.DestinationIP.IsValid() &&
		t.SourceIP.Is4() == t.DestinationIP.Is4()
}

// String returns a stable, human-readable tuple.
func (t Tuple) String() string {
	return fmt.Sprintf(
		"%s -> %s",
		netip.AddrPortFrom(t.SourceIP, t.SourcePort),
		netip.AddrPortFrom(t.DestinationIP, t.DestinationPort),
	)
}

// Counter contains packet and byte counters for one direction.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Counters contains both conntrack directions.
type Counters struct {
	Available bool    `json:"available"`
	Original  Counter `json:"original"`
	Reply     Counter `json:"reply"`
}

// NAT describes whether NAT flags were observed. Tuple fields are populated
// only when the underlying source exposes explicit NAT tuples.
type NAT struct {
	Detected        bool   `json:"detected"`
	SourceNAT       bool   `json:"source_nat"`
	DestinationNAT  bool   `json:"destination_nat"`
	SourceNATDone   bool   `json:"source_nat_done"`
	DestinationDone bool   `json:"destination_nat_done"`
	Original        *Tuple `json:"original_tuple,omitempty"`
	Reply           *Tuple `json:"reply_tuple,omitempty"`
}

// Attribution captures optional process, user and container context.
type Attribution struct {
	PID         uint32     `json:"pid,omitempty"`
	ProcessName string     `json:"process_name,omitempty"`
	UserID      string     `json:"user_id,omitempty"`
	UserName    string     `json:"user_name,omitempty"`
	ContainerID string     `json:"container_id,omitempty"`
	Source      string     `json:"source,omitempty"`
	Confidence  Confidence `json:"confidence"`
}

// Event is the normalized, source-independent connection event.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	EventID       string    `json:"event_id"`
	FlowID        string    `json:"flow_id,omitempty"`
	NodeID        string    `json:"node_id"`
	Source        string    `json:"source"`
	SourceVersion string    `json:"source_version,omitempty"`
	EventType     EventType `json:"event_type"`

	ObservedAt time.Time  `json:"observed_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	NetNSID    uint64     `json:"netns_id,omitempty"`
	Zone       uint16     `json:"zone"`

	Protocol Protocol `json:"protocol"`
	Original Tuple    `json:"original"`
	Reply    Tuple    `json:"reply"`
	NAT      NAT      `json:"nat"`

	State       string    `json:"state,omitempty"`
	Direction   Direction `json:"direction"`
	Replied     bool      `json:"replied"`
	Assured     bool      `json:"assured"`
	Preexisting bool      `json:"preexisting"`

	Counters    Counters    `json:"counters"`
	Attribution Attribution `json:"attribution"`

	Complete      bool     `json:"complete"`
	GapID         string   `json:"gap_id,omitempty"`
	MissingFields []string `json:"missing_fields,omitempty"`
}

// Flow is the materialized lifecycle record derived from normalized events.
type Flow struct {
	SchemaVersion string `json:"schema_version"`
	FlowID        string `json:"flow_id"`
	NodeID        string `json:"node_id"`
	Source        string `json:"source"`

	NetNSID  uint64   `json:"netns_id,omitempty"`
	Zone     uint16   `json:"zone"`
	Protocol Protocol `json:"protocol"`
	Original Tuple    `json:"original"`
	Reply    Tuple    `json:"reply"`
	NAT      NAT      `json:"nat"`

	Direction Direction `json:"direction"`
	State     string    `json:"state,omitempty"`
	Open      bool      `json:"open"`

	FirstSeenAt time.Time  `json:"first_seen_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`

	Replied     bool `json:"replied"`
	Assured     bool `json:"assured"`
	Preexisting bool `json:"preexisting"`

	Counters    Counters    `json:"counters"`
	Attribution Attribution `json:"attribution"`

	Complete      bool     `json:"complete"`
	GapID         string   `json:"gap_id,omitempty"`
	MissingFields []string `json:"missing_fields,omitempty"`
}

// CaptureGap records a period or volume for which observation is incomplete.
type CaptureGap struct {
	GapID     string     `json:"gap_id"`
	NodeID    string     `json:"node_id"`
	Source    string     `json:"source"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Reason    string     `json:"reason"`
	LostCount uint64     `json:"lost_count"`
	Details   string     `json:"details,omitempty"`
}

// Validate checks the minimum fields needed to persist an event.
func (e Event) Validate() error {
	if e.EventID == "" {
		return errors.New("event_id is required")
	}
	if e.NodeID == "" {
		return errors.New("node_id is required")
	}
	if e.Source == "" {
		return errors.New("source is required")
	}
	if !isKnownEventType(e.EventType) {
		return fmt.Errorf("unsupported event type %q", e.EventType)
	}
	if e.ObservedAt.IsZero() {
		return errors.New("observed_at is required")
	}
	if e.Protocol != ProtocolTCP && e.Protocol != ProtocolUDP {
		return fmt.Errorf("unsupported protocol %q", e.Protocol)
	}
	if !e.Original.IsValid() {
		return errors.New("original tuple is invalid")
	}
	if e.Reply.SourceIP.IsValid() && !e.Reply.IsValid() {
		return errors.New("reply tuple is invalid")
	}
	if !e.Direction.Valid() {
		return fmt.Errorf("unsupported direction %q", e.Direction)
	}

	return nil
}

// Validate checks that a flow can be persisted and queried.
func (f Flow) Validate() error {
	if f.FlowID == "" {
		return errors.New("flow_id is required")
	}
	if f.NodeID == "" {
		return errors.New("node_id is required")
	}
	if f.Source == "" {
		return errors.New("source is required")
	}
	if !f.Original.IsValid() {
		return errors.New("original tuple is invalid")
	}
	if f.Protocol != ProtocolTCP && f.Protocol != ProtocolUDP {
		return fmt.Errorf("unsupported protocol %q", f.Protocol)
	}
	if f.Reply.SourceIP.IsValid() && !f.Reply.IsValid() {
		return errors.New("reply tuple is invalid")
	}
	if f.FirstSeenAt.IsZero() || f.LastSeenAt.IsZero() {
		return errors.New("flow timestamps are required")
	}
	if f.LastSeenAt.Before(f.FirstSeenAt) {
		return errors.New("last_seen_at cannot be before first_seen_at")
	}
	if !f.Direction.Valid() {
		return fmt.Errorf("unsupported direction %q", f.Direction)
	}

	return nil
}
