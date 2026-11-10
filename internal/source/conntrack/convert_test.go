//go:build linux

package conntrack

import (
	"net/netip"
	"testing"
	"time"

	ct "github.com/ti-mo/conntrack"

	"flowaudit/internal/flow"
)

func TestConvertFlowAllowsMissingTCPProtoInfo(t *testing.T) {
	input := testConntrackFlow()
	input.ProtoInfo.TCP = nil

	event, supported, err := convertFlow(
		flow.EventTypeNew,
		input,
		convertOptions{
			NodeID:           "node-1",
			SourceVersion:    "test",
			LocalIPs:         map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.10"): {}},
			IncludeUnreplied: true,
		},
		time.Now(),
	)
	if err != nil {
		t.Fatalf("convertFlow() error = %v", err)
	}
	if !supported {
		t.Fatal("convertFlow() returned unsupported TCP flow")
	}
	if event.State != "" {
		t.Fatalf("State = %q, want empty state", event.State)
	}
}

func TestConvertFlowIncludesTCPState(t *testing.T) {
	input := testConntrackFlow()
	input.ProtoInfo.TCP = &ct.ProtoInfoTCP{State: 3}

	event, supported, err := convertFlow(
		flow.EventTypeNew,
		input,
		convertOptions{
			NodeID:           "node-1",
			SourceVersion:    "test",
			LocalIPs:         map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.10"): {}},
			IncludeUnreplied: true,
		},
		time.Now(),
	)
	if err != nil {
		t.Fatalf("convertFlow() error = %v", err)
	}
	if !supported {
		t.Fatal("convertFlow() returned unsupported TCP flow")
	}
	if event.State != "ESTABLISHED" {
		t.Fatalf("State = %q, want ESTABLISHED", event.State)
	}
}

func testConntrackFlow() ct.Flow {
	return ct.Flow{
		TupleOrig: ct.Tuple{
			IP: ct.IPTuple{
				SourceAddress:      netip.MustParseAddr("10.0.0.10"),
				DestinationAddress: netip.MustParseAddr("1.1.1.1"),
			},
			Proto: ct.ProtoTuple{
				Protocol:        6,
				SourcePort:      52344,
				DestinationPort: 443,
			},
		},
		TupleReply: ct.Tuple{
			IP: ct.IPTuple{
				SourceAddress:      netip.MustParseAddr("1.1.1.1"),
				DestinationAddress: netip.MustParseAddr("10.0.0.10"),
			},
			Proto: ct.ProtoTuple{
				Protocol:        6,
				SourcePort:      443,
				DestinationPort: 52344,
			},
		},
		ProtoInfo: ct.ProtoInfo{TCP: &ct.ProtoInfoTCP{State: 3}},
	}
}
