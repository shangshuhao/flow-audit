package flow

import (
	"fmt"
	"net/netip"
	"strings"
)

const SchemaVersion = "1.0"

const (
	EventTypeNew     EventType = "new"
	EventTypeUpdate  EventType = "update"
	EventTypeDestroy EventType = "destroy"
	EventTypeImport  EventType = "import"
)

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
	DirectionLocal    Direction = "local"
	DirectionForward  Direction = "forward"
	DirectionUnknown  Direction = "unknown"
)

const (
	ConfidenceUnknown  Confidence = "unknown"
	ConfidenceInferred Confidence = "inferred"
	ConfidenceObserved Confidence = "observed"
)

const (
	GapReasonNetlinkENOBUFS       = "netlink_enobufs"
	GapReasonQueueOverflow        = "queue_overflow"
	GapReasonParseFailure         = "parse_failure"
	GapReasonDatabaseUnavailable  = "database_unavailable"
	GapReasonAgentRestart         = "agent_restart"
	GapReasonSourceDisconnected   = "source_disconnected"
	GapReasonIncompleteEvent      = "incomplete_event"
	GapReasonPersistenceBacklog   = "persistence_backlog"
	GapReasonUnsupportedDataEvent = "unsupported_event"
)

// EventType describes the lifecycle operation represented by an event.
type EventType string

// Protocol is the transport protocol stored in the normalized model.
type Protocol string

// Direction is expressed from the perspective of the local node.
type Direction string

// Confidence records how attribution information was obtained.
type Confidence string

// Valid reports whether the event type is part of the v1 schema.
func (t EventType) Valid() bool {
	return isKnownEventType(t)
}

// Valid reports whether the direction is part of the v1 schema.
func (d Direction) Valid() bool {
	switch d {
	case DirectionInbound, DirectionOutbound, DirectionLocal, DirectionForward, DirectionUnknown:
		return true
	default:
		return false
	}
}

// ParseProtocol maps an IP protocol number to a supported protocol.
func ParseProtocol(number uint8) (Protocol, error) {
	const (
		ipProtocolTCP = 6
		ipProtocolUDP = 17
	)

	switch number {
	case ipProtocolTCP:
		return ProtocolTCP, nil
	case ipProtocolUDP:
		return ProtocolUDP, nil
	default:
		return "", fmt.Errorf("unsupported protocol number %d", number)
	}
}

// DetectDirection derives a direction from local addresses.
func DetectDirection(tuple Tuple, localIPs map[netip.Addr]struct{}) Direction {
	if !tuple.IsValid() {
		return DirectionUnknown
	}

	srcLocal := isLocal(tuple.SourceIP, localIPs)
	dstLocal := isLocal(tuple.DestinationIP, localIPs)

	switch {
	case srcLocal && dstLocal:
		return DirectionLocal
	case srcLocal:
		return DirectionOutbound
	case dstLocal:
		return DirectionInbound
	case len(localIPs) == 0:
		return DirectionUnknown
	default:
		return DirectionForward
	}
}

// NormalizeState converts internal protocol state names to stable labels.
func NormalizeState(state string) string {
	return strings.ToUpper(strings.TrimSpace(state))
}

// isKnownEventType reports whether an event type can be persisted.
func isKnownEventType(t EventType) bool {
	switch t {
	case EventTypeNew, EventTypeUpdate, EventTypeDestroy, EventTypeImport:
		return true
	default:
		return false
	}
}

// isLocal reports whether an address belongs to the current host.
func isLocal(addr netip.Addr, localIPs map[netip.Addr]struct{}) bool {
	_, ok := localIPs[addr.Unmap()]
	return ok
}
