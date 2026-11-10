package httpapi

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"flowaudit/internal/flow"
	"flowaudit/internal/version"
)

const exportPageLimit = 500

// handleExport streams filtered evidence as JSONL or CSV.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	query, err := parseQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_argument", err)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "jsonl"
	}
	if format != "jsonl" && format != "csv" {
		writeError(w, http.StatusBadRequest, "invalid_argument", errors.New("format must be jsonl or csv"))
		return
	}

	start, end, err := parseTimeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_argument", err)
		return
	}
	gapEnd := time.Now().UTC()
	if end != nil {
		gapEnd = *end
	}
	gapStart := gapEnd.Add(-defaultGapWindow)
	if start != nil {
		gapStart = *start
	}
	gaps, err := s.store.QueryGaps(r.Context(), gapStart, gapEnd)
	if err != nil {
		s.logger.Error("query export gaps failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}

	filename := fmt.Sprintf("flow-audit-%s.%s", time.Now().UTC().Format("20060102T150405Z"), format)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		err = s.exportCSV(r, w, query)
	default:
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		err = s.exportJSONL(r, w, query, gaps)
	}
	if err != nil {
		s.logger.Error("export failed", "format", format, "error", err)
	}
}

// exportJSONL writes metadata, capture gaps, and paginated Flow records.
func (s *Server) exportJSONL(
	r *http.Request,
	w http.ResponseWriter,
	query flow.Query,
	gaps []flow.CaptureGap,
) error {
	encoder := json.NewEncoder(w)
	metadata := map[string]any{
		"type":           "metadata",
		"version":        version.Version,
		"schema_version": flow.SchemaVersion,
		"exported_at":    time.Now().UTC(),
		"query":          query,
		"capture_gaps":   gaps,
	}
	if err := encoder.Encode(metadata); err != nil {
		return fmt.Errorf("write export metadata: %w", err)
	}

	for {
		page, err := s.store.QueryFlows(r.Context(), query)
		if err != nil {
			return fmt.Errorf("query export page: %w", err)
		}
		for _, item := range page.Items {
			record := struct {
				Type string    `json:"type"`
				Flow flow.Flow `json:"flow"`
			}{
				Type: "flow",
				Flow: item,
			}
			if err := encoder.Encode(record); err != nil {
				return fmt.Errorf("write export flow: %w", err)
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		query.Cursor = page.NextCursor
		query.Limit = exportPageLimit
	}
}

// exportCSV streams the primary Flow fields with bounded database pages.
func (s *Server) exportCSV(r *http.Request, w http.ResponseWriter, query flow.Query) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{
		"flow_id",
		"first_seen_at",
		"last_seen_at",
		"closed_at",
		"direction",
		"protocol",
		"original_source_ip",
		"original_source_port",
		"original_destination_ip",
		"original_destination_port",
		"state",
		"open",
		"replied",
		"complete",
		"original_packets",
		"original_bytes",
		"reply_packets",
		"reply_bytes",
	}); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for {
		page, err := s.store.QueryFlows(r.Context(), query)
		if err != nil {
			return fmt.Errorf("query CSV page: %w", err)
		}
		for _, item := range page.Items {
			closedAt := ""
			if item.ClosedAt != nil {
				closedAt = item.ClosedAt.UTC().Format(time.RFC3339Nano)
			}
			if err := writer.Write([]string{
				item.FlowID,
				item.FirstSeenAt.UTC().Format(time.RFC3339Nano),
				item.LastSeenAt.UTC().Format(time.RFC3339Nano),
				closedAt,
				string(item.Direction),
				string(item.Protocol),
				item.Original.SourceIP.String(),
				strconv.Itoa(int(item.Original.SourcePort)),
				item.Original.DestinationIP.String(),
				strconv.Itoa(int(item.Original.DestinationPort)),
				item.State,
				strconv.FormatBool(item.Open),
				strconv.FormatBool(item.Replied),
				strconv.FormatBool(item.Complete),
				strconv.FormatUint(item.Counters.Original.Packets, 10),
				strconv.FormatUint(item.Counters.Original.Bytes, 10),
				strconv.FormatUint(item.Counters.Reply.Packets, 10),
				strconv.FormatUint(item.Counters.Reply.Bytes, 10),
			}); err != nil {
				return fmt.Errorf("write CSV flow: %w", err)
			}
		}
		if page.NextCursor == "" {
			writer.Flush()
			return writer.Error()
		}
		query.Cursor = page.NextCursor
		query.Limit = exportPageLimit
	}
}
