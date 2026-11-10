// Package httpapi provides read-only HTTP APIs and the embedded user interface.
package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"flowaudit/internal/health"
	"flowaudit/internal/store"
	"flowaudit/internal/telemetry"
	"flowaudit/internal/version"
)

const defaultGapWindow = 24 * time.Hour

// Server exposes the read-only HTTP API and embedded UI.
type Server struct {
	store          store.Store
	status         *health.Status
	metrics        *telemetry.Metrics
	logger         *slog.Logger
	authToken      string
	metricsEnabled bool
}

// New creates an HTTP API server.
func New(
	storage store.Store,
	status *health.Status,
	metrics *telemetry.Metrics,
	logger *slog.Logger,
	authToken string,
	metricsEnabled bool,
) (*Server, error) {
	if storage == nil {
		return nil, errors.New("store is required")
	}
	if status == nil {
		return nil, errors.New("status is required")
	}
	if metrics == nil {
		return nil, errors.New("metrics is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}

	return &Server{
		store:          storage,
		status:         status,
		metrics:        metrics,
		logger:         logger,
		authToken:      authToken,
		metricsEnabled: metricsEnabled,
	}, nil
}

// Handler returns the complete HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	if s.metricsEnabled {
		mux.HandleFunc("GET /metrics", s.metrics.Handler().ServeHTTP)
	}
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/flows", s.handleFlows)
	mux.HandleFunc("GET /api/v1/flows/{flowID}", s.handleFlow)
	mux.HandleFunc("GET /api/v1/flows/{flowID}/events", s.handleFlowEvents)
	mux.HandleFunc("GET /api/v1/capture-gaps", s.handleGaps)
	mux.HandleFunc("GET /api/v1/export", s.handleExport)
	mux.HandleFunc("GET /", s.handleUI)

	return s.recoverMiddleware(s.requestIDMiddleware(s.authMiddleware(mux)))
}

// handleHealth reports process liveness without checking dependencies.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version.Version,
	})
}

// handleReady reports whether collection and storage can provide fresh data.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.status.Snapshot()
	statusCode := http.StatusOK
	state := "ready"
	if !snapshot.Ready() {
		statusCode = http.StatusServiceUnavailable
		state = "not_ready"
	}

	writeJSON(w, statusCode, map[string]any{
		"status": state,
		"detail": snapshot,
	})
}

// handleStatus returns detailed runtime health and build information.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"runtime": s.status.Snapshot(),
		"version": map[string]string{
			"version":    version.Version,
			"commit":     version.Commit,
			"build_date": version.BuildDate,
		},
	})
}

// handleFlows returns a filtered page of materialized Flow records.
func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	query, err := parseQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_argument", err)
		return
	}

	page, err := s.store.QueryFlows(r.Context(), query)
	if err != nil {
		s.logger.Error("query flows failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}

	writeJSON(w, http.StatusOK, page)
}

// handleFlow returns one Flow by its stable identifier.
func (s *Server) handleFlow(w http.ResponseWriter, r *http.Request) {
	flowID := r.PathValue("flowID")
	item, err := s.store.GetFlow(r.Context(), flowID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", err)
		return
	}
	if err != nil {
		s.logger.Error("get flow failed", "flow_id", flowID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}

	writeJSON(w, http.StatusOK, item)
}

// handleFlowEvents returns the ordered lifecycle history for a Flow.
func (s *Server) handleFlowEvents(w http.ResponseWriter, r *http.Request) {
	flowID := r.PathValue("flowID")
	items, err := s.store.ListFlowEvents(r.Context(), flowID)
	if err != nil {
		s.logger.Error("list flow events failed", "flow_id", flowID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleGaps returns observation gaps overlapping the requested time range.
func (s *Server) handleGaps(w http.ResponseWriter, r *http.Request) {
	start, end, err := parseTimeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_argument", err)
		return
	}
	if start == nil {
		value := end.Add(-defaultGapWindow)
		start = &value
	}

	items, err := s.store.QueryGaps(r.Context(), *start, *end)
	if err != nil {
		s.logger.Error("query capture gaps failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
