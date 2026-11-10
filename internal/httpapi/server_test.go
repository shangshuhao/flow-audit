package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowaudit/internal/flow"
	"flowaudit/internal/health"
	"flowaudit/internal/store"
	"flowaudit/internal/store/sqlite"
	"flowaudit/internal/telemetry"
)

func TestServerQueriesFlowAndExports(t *testing.T) {
	ctx := context.Background()
	storage, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		if closeErr := storage.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	now := time.Date(2026, time.November, 9, 3, 0, 0, 0, time.UTC)
	event, item := apiFixtures(now)
	if err := storage.ApplyBatch(ctx, []store.Record{{Event: event, Flow: item}}); err != nil {
		t.Fatalf("ApplyBatch() error = %v", err)
	}

	status := health.New()
	status.SetSource(health.StateHealthy, nil)
	status.SetStore(health.StateHealthy, nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	metrics := telemetry.New()
	server, err := New(storage, status, metrics, logger, "", true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	recorder := performRequest(server.Handler(), "/api/v1/flows?ip=1.1.1.1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/flows status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var page flow.Page
	if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].FlowID != item.FlowID {
		t.Fatalf("unexpected page: %+v", page)
	}

	recorder = performRequest(server.Handler(), "/api/v1/export?format=jsonl&ip=1.1.1.1")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET export status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"type":"metadata"`) ||
		!strings.Contains(recorder.Body.String(), `"type":"flow"`) {
		t.Fatalf("unexpected export body: %s", recorder.Body.String())
	}

	recorder = performRequest(server.Handler(), "/")
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte("Flow Audit")) {
		t.Fatalf("GET / status = %d body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = performRequest(server.Handler(), "/readyz")
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /readyz status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func performRequest(handler http.Handler, target string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}

func apiFixtures(now time.Time) (flow.Event, flow.Flow) {
	event := flow.Event{
		SchemaVersion: flow.SchemaVersion,
		EventID:       "event-api",
		FlowID:        "flow-api",
		NodeID:        "node-api",
		Source:        "conntrack",
		EventType:     flow.EventTypeNew,
		ObservedAt:    now,
		Protocol:      flow.ProtocolTCP,
		Original: flow.Tuple{
			SourceIP:        netip.MustParseAddr("10.0.0.10"),
			SourcePort:      52344,
			DestinationIP:   netip.MustParseAddr("1.1.1.1"),
			DestinationPort: 443,
		},
		Direction:   flow.DirectionOutbound,
		State:       "ESTABLISHED",
		Counters:    flow.Counters{Available: true},
		Attribution: flow.Attribution{Confidence: flow.ConfidenceUnknown},
		Complete:    true,
	}
	item := flow.Flow{
		SchemaVersion: flow.SchemaVersion,
		FlowID:        event.FlowID,
		NodeID:        event.NodeID,
		Source:        event.Source,
		Protocol:      event.Protocol,
		Original:      event.Original,
		Direction:     event.Direction,
		State:         event.State,
		Open:          true,
		FirstSeenAt:   now,
		LastSeenAt:    now,
		Counters:      event.Counters,
		Attribution:   event.Attribution,
		Complete:      true,
	}

	return event, item
}
