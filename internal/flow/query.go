package flow

import (
	"net/netip"
	"time"
)

// Query defines filters for connection searches.
type Query struct {
	Start       *time.Time
	End         *time.Time
	Protocol    Protocol
	IP          *netip.Addr
	SourceIP    *netip.Addr
	DestIP      *netip.Addr
	SourcePort  *uint16
	DestPort    *uint16
	Direction   Direction
	State       string
	Open        *bool
	Replied     *bool
	Preexisting *bool
	Complete    *bool
	Limit       int
	Cursor      string
}

// Summary contains aggregate information for a query result.
type Summary struct {
	Count         int64  `json:"count"`
	OpenCount     int64  `json:"open_count"`
	OriginalBytes uint64 `json:"original_bytes"`
	ReplyBytes    uint64 `json:"reply_bytes"`
}

// Page is a cursor-based connection query result.
type Page struct {
	Items      []Flow  `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
	Summary    Summary `json:"summary"`
}
