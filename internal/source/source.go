// Package source defines telemetry source contracts and capabilities.
package source

import (
	"context"

	"flowaudit/internal/flow"
)

// Capabilities describes fields exposed by a data source.
type Capabilities struct {
	ReplyTuple  bool
	NAT         bool
	NATTuples   bool
	Counters    bool
	TCPState    bool
	Zone        bool
	PID         bool
	ContainerID bool
	Layer7      bool
	CaptureGaps bool
}

// Source converts a concrete telemetry source into normalized Flow events.
type Source interface {
	Name() string
	Capabilities() Capabilities
	Run(context.Context, chan<- flow.Event) error
}
