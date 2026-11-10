// Package telemetry records and exposes process-local operational metrics.
package telemetry

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics contains process-local counters exposed in Prometheus text format.
type Metrics struct {
	EventsReceived   atomic.Uint64
	EventsSupported  atomic.Uint64
	EventsDropped    atomic.Uint64
	ParseErrors      atomic.Uint64
	StoreWriteErrors atomic.Uint64
	CaptureGaps      atomic.Uint64
	FlowsWritten     atomic.Uint64
	ActiveFlows      atomic.Int64
	LastQueueDepth   atomic.Int64
	NetlinkENOBUFS   atomic.Uint64

	mu            sync.Mutex
	eventsByType  map[string]uint64
	dropsByReason map[string]uint64
}

// New creates an empty metrics registry.
func New() *Metrics {
	return &Metrics{
		eventsByType:  make(map[string]uint64),
		dropsByReason: make(map[string]uint64),
	}
}

// ObserveEvent increments event counters.
func (m *Metrics) ObserveEvent(eventType string, supported bool) {
	m.EventsReceived.Add(1)
	if supported {
		m.EventsSupported.Add(1)
	}

	m.mu.Lock()
	m.eventsByType[eventType]++
	m.mu.Unlock()
}

// Drop records a dropped event or batch.
func (m *Metrics) Drop(reason string, count uint64) {
	m.EventsDropped.Add(count)

	m.mu.Lock()
	m.dropsByReason[reason] += count
	m.mu.Unlock()
}

// Handler returns the /metrics HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		writeCounter(w, "flowaudit_events_received_total", "Normalized events received.", m.EventsReceived.Load())
		writeCounter(w, "flowaudit_events_supported_total", "Events supported by the active source.", m.EventsSupported.Load())
		writeCounter(w, "flowaudit_events_dropped_total", "Events dropped by the agent.", m.EventsDropped.Load())
		writeCounter(w, "flowaudit_parse_errors_total", "Events that failed parsing or validation.", m.ParseErrors.Load())
		writeCounter(w, "flowaudit_store_write_errors_total", "Storage write failures.", m.StoreWriteErrors.Load())
		writeCounter(w, "flowaudit_capture_gaps_total", "Recorded observation gaps.", m.CaptureGaps.Load())
		writeCounter(w, "flowaudit_flows_written_total", "Flow snapshot writes.", m.FlowsWritten.Load())
		writeCounter(w, "flowaudit_netlink_enobufs_total", "Observed Netlink ENOBUFS failures.", m.NetlinkENOBUFS.Load())
		writeGauge(w, "flowaudit_active_flows", "Currently open materialized flows.", m.ActiveFlows.Load())
		writeGauge(w, "flowaudit_queue_depth", "Most recently observed processing queue depth.", m.LastQueueDepth.Load())

		m.mu.Lock()
		types := sortedKeys(m.eventsByType)
		for _, key := range types {
			writeLabeledCounter(
				w,
				"flowaudit_source_events_total",
				"Events received by event type.",
				"type",
				key,
				m.eventsByType[key],
			)
		}
		reasons := sortedKeys(m.dropsByReason)
		for _, key := range reasons {
			writeLabeledCounter(
				w,
				"flowaudit_source_events_dropped_total",
				"Dropped events by reason.",
				"reason",
				key,
				m.dropsByReason[key],
			)
		}
		m.mu.Unlock()
	})
}

// writeCounter emits one unlabeled Prometheus counter.
func writeCounter(w http.ResponseWriter, name, help string, value uint64) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, value)
}

// writeGauge emits one unlabeled Prometheus gauge.
func writeGauge(w http.ResponseWriter, name, help string, value int64) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
}

// writeLabeledCounter emits a counter with one safely quoted label.
func writeLabeledCounter(
	w http.ResponseWriter,
	name string,
	help string,
	labelName string,
	labelValue string,
	value uint64,
) {
	_, _ = fmt.Fprintf(
		w,
		"# HELP %s %s\n# TYPE %s counter\n%s{%s=%q} %d\n",
		name,
		help,
		name,
		name,
		labelName,
		labelValue,
		value,
	)
}

// sortedKeys returns deterministic metric label ordering.
func sortedKeys(values map[string]uint64) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

// EscapeMetricLabel sanitizes arbitrary source strings for metric labels.
func EscapeMetricLabel(value string) string {
	return strconv.Quote(strings.TrimSpace(value))
}
