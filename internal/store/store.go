// Package store defines the persistence contract used by the application.
package store

import (
	"context"
	"errors"
	"time"

	"flowaudit/internal/flow"
)

// ErrNotFound indicates that a requested record does not exist.
var ErrNotFound = errors.New("record not found")

// Record couples one normalized event with its materialized flow snapshot.
type Record struct {
	Event flow.Event
	Flow  flow.Flow
}

// Store defines the persistence boundary used by the application.
type Store interface {
	Close() error
	Ping(context.Context) error
	RestoreOpenFlows(context.Context) ([]flow.Flow, error)
	ApplyBatch(context.Context, []Record) error
	GetFlow(context.Context, string) (flow.Flow, error)
	QueryFlows(context.Context, flow.Query) (flow.Page, error)
	ListFlowEvents(context.Context, string) ([]flow.Event, error)
	AppendGap(context.Context, flow.CaptureGap) error
	QueryGaps(context.Context, time.Time, time.Time) ([]flow.CaptureGap, error)
	DeleteBefore(context.Context, time.Time, time.Time) error
}
