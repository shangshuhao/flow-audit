//go:build linux

package conntrack

import (
	"fmt"
	"net/netip"
	"time"

	ct "github.com/ti-mo/conntrack"

	"flowaudit/internal/flow"
)

// convertOptions carries event-independent metadata for source conversion.
type convertOptions struct {
	NodeID           string
	SourceVersion    string
	LocalIPs         map[netip.Addr]struct{}
	NetNSID          uint64
	IncludeUnreplied bool
}

// convertFlow maps one source-specific conntrack snapshot into a FlowEvent.
func convertFlow(
	eventType flow.EventType,
	input ct.Flow,
	options convertOptions,
	now time.Time,
) (flow.Event, bool, error) {
	protocol, err := flow.ParseProtocol(input.TupleOrig.Proto.Protocol)
	if err != nil {
		return flow.Event{}, false, nil
	}

	original, err := convertTuple(input.TupleOrig)
	if err != nil {
		return flow.Event{}, false, fmt.Errorf("convert original tuple: %w", err)
	}
	reply, err := convertTuple(input.TupleReply)
	if err != nil {
		return flow.Event{}, false, fmt.Errorf("convert reply tuple: %w", err)
	}

	replied := input.Status.SeenReply()
	if eventType == flow.EventTypeDestroy && !replied && !options.IncludeUnreplied {
		return flow.Event{}, false, nil
	}

	eventID, err := flow.NewEventID()
	if err != nil {
		return flow.Event{}, false, err
	}

	missingFields := make([]string, 0)
	if !reply.IsValid() {
		missingFields = append(missingFields, "reply_tuple")
	}

	countersAvailable := input.CountersOrig.Packets > 0 ||
		input.CountersOrig.Bytes > 0 ||
		input.CountersReply.Packets > 0 ||
		input.CountersReply.Bytes > 0

	var startedAt *time.Time
	if !input.Timestamp.Start.IsZero() {
		value := input.Timestamp.Start.UTC()
		startedAt = &value
	}

	// ProtoInfo is optional on some events and must not be dereferenced blindly.
	state := ""
	if protocol == flow.ProtocolTCP && input.ProtoInfo.TCP != nil {
		state = tcpStateName(input.ProtoInfo.TCP.State)
	}

	event := flow.Event{
		SchemaVersion: flow.SchemaVersion,
		EventID:       eventID,
		NodeID:        options.NodeID,
		Source:        "conntrack",
		SourceVersion: options.SourceVersion,
		EventType:     eventType,
		ObservedAt:    now.UTC(),
		StartedAt:     startedAt,
		NetNSID:       options.NetNSID,
		Zone:          input.Zone,
		Protocol:      protocol,
		Original:      original,
		Reply:         reply,
		// The pure-Go library exposes NAT flags; translated tuples are optional.
		NAT: flow.NAT{
			Detected:        input.Status.SrcNAT() || input.Status.DstNAT(),
			SourceNAT:       input.Status.SrcNAT(),
			DestinationNAT:  input.Status.DstNAT(),
			SourceNATDone:   input.Status.SrcNATDone(),
			DestinationDone: input.Status.DstNATDone(),
		},
		State:       state,
		Direction:   flow.DetectDirection(original, options.LocalIPs),
		Replied:     replied,
		Assured:     input.Status.Assured(),
		Preexisting: eventType == flow.EventTypeImport,
		Counters: flow.Counters{
			Available: countersAvailable,
			Original: flow.Counter{
				Packets: input.CountersOrig.Packets,
				Bytes:   input.CountersOrig.Bytes,
			},
			Reply: flow.Counter{
				Packets: input.CountersReply.Packets,
				Bytes:   input.CountersReply.Bytes,
			},
		},
		Attribution:   flow.Attribution{Confidence: flow.ConfidenceUnknown},
		Complete:      len(missingFields) == 0,
		MissingFields: missingFields,
	}

	return event, true, nil
}

// safeConvertFlow contains malformed third-party events as ordinary errors.
func safeConvertFlow(
	eventType flow.EventType,
	input ct.Flow,
	options convertOptions,
	now time.Time,
) (event flow.Event, supported bool, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			event = flow.Event{}
			supported = false
			err = fmt.Errorf("convert conntrack flow: recovered panic: %v", recovered)
		}
	}()

	return convertFlow(eventType, input, options, now)
}

// convertTuple converts a conntrack tuple while preserving an absent tuple.
func convertTuple(input ct.Tuple) (flow.Tuple, error) {
	if !input.IP.SourceAddress.IsValid() || !input.IP.DestinationAddress.IsValid() {
		return flow.Tuple{}, nil
	}

	return flow.Tuple{
		SourceIP:        input.IP.SourceAddress.Unmap(),
		SourcePort:      input.Proto.SourcePort,
		DestinationIP:   input.IP.DestinationAddress.Unmap(),
		DestinationPort: input.Proto.DestinationPort,
	}, nil
}

// tcpStateName maps Linux conntrack TCP state numbers to stable labels.
func tcpStateName(state uint8) string {
	switch state {
	case 0:
		return "NONE"
	case 1:
		return "SYN_SENT"
	case 2:
		return "SYN_RECV"
	case 3:
		return "ESTABLISHED"
	case 4:
		return "FIN_WAIT"
	case 5:
		return "CLOSE_WAIT"
	case 6:
		return "LAST_ACK"
	case 7:
		return "TIME_WAIT"
	case 8:
		return "CLOSE"
	case 9:
		return "LISTEN"
	default:
		return fmt.Sprintf("UNKNOWN_%d", state)
	}
}
