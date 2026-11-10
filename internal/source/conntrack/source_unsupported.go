//go:build !linux

package conntrack

import (
	"context"
	"errors"

	"flowaudit/internal/flow"
	"flowaudit/internal/source"
)

// Source is unavailable outside Linux.
type Source struct{}

// Options configures the conntrack source.
type Options struct {
	NodeID             string
	IncludePreexisting bool
	IncludeUnreplied   bool
	NetlinkReadBuffer  int
	EventQueueSize     int
}

// New returns an explicit unsupported-platform error.
func New(options Options) (*Source, error) {
	return &Source{}, errors.New("conntrack source is only supported on Linux")
}

// Name returns the stable source name on unsupported platforms.
func (s *Source) Name() string {
	return "conntrack"
}

// Capabilities returns no capabilities when conntrack is unavailable.
func (s *Source) Capabilities() source.Capabilities {
	return source.Capabilities{}
}

// Run returns the platform limitation as an explicit error.
func (s *Source) Run(context.Context, chan<- flow.Event) error {
	return errors.New("conntrack source is only supported on Linux")
}
