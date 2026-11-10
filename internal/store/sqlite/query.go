package sqlite

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"flowaudit/internal/flow"
)

const (
	defaultQueryLimit = 50
	maxQueryLimit     = 500
)

// QueryFlows returns a filtered page of Flow records.
func (s *Store) QueryFlows(ctx context.Context, query flow.Query) (flow.Page, error) {
	where, args, err := buildFlowWhere(query)
	if err != nil {
		return flow.Page{}, err
	}

	limit := query.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}
	if limit > maxQueryLimit {
		limit = maxQueryLimit
	}

	cursorClause, cursorArgs, err := decodeCursor(query.Cursor)
	if err != nil {
		return flow.Page{}, err
	}
	if cursorClause != "" {
		if where == "" {
			where = " WHERE " + cursorClause
		} else {
			where += " AND " + cursorClause
		}
		args = append(args, cursorArgs...)
	}

	summary, err := s.querySummary(ctx, where, args)
	if err != nil {
		return flow.Page{}, err
	}

	statement := `
SELECT flow_id, last_seen_ns, payload_json
FROM flows` + where + `
ORDER BY last_seen_ns DESC, flow_id DESC
LIMIT ?`
	queryArgs := append(append([]any(nil), args...), limit+1)

	rows, err := s.db.QueryContext(ctx, statement, queryArgs...)
	if err != nil {
		return flow.Page{}, fmt.Errorf("query flows: %w", err)
	}
	defer rows.Close()

	type rowItem struct {
		flowID     string
		lastSeenNS int64
		payload    string
	}
	rowItems := make([]rowItem, 0, limit+1)
	for rows.Next() {
		var item rowItem
		if err := rows.Scan(&item.flowID, &item.lastSeenNS, &item.payload); err != nil {
			return flow.Page{}, fmt.Errorf("scan flow row: %w", err)
		}
		rowItems = append(rowItems, item)
	}
	if err := rows.Err(); err != nil {
		return flow.Page{}, fmt.Errorf("iterate flow rows: %w", err)
	}

	nextCursor := ""
	if len(rowItems) > limit {
		rowItems = rowItems[:limit]
		last := rowItems[len(rowItems)-1]
		nextCursor = encodeCursor(last.lastSeenNS, last.flowID)
	}

	items := make([]flow.Flow, 0, len(rowItems))
	for _, row := range rowItems {
		var item flow.Flow
		if err := json.Unmarshal([]byte(row.payload), &item); err != nil {
			return flow.Page{}, fmt.Errorf("decode flow %q: %w", row.flowID, err)
		}
		items = append(items, item)
	}

	return flow.Page{
		Items:      items,
		NextCursor: nextCursor,
		Summary:    summary,
	}, nil
}

// querySummary calculates totals for the same filters as the page query.
func (s *Store) querySummary(ctx context.Context, where string, args []any) (flow.Summary, error) {
	statement := `
SELECT
    COUNT(1),
    COALESCE(SUM(CASE WHEN open = 1 THEN 1 ELSE 0 END), 0),
    COALESCE(SUM(original_bytes), 0),
    COALESCE(SUM(reply_bytes), 0)
FROM flows` + where

	var summary flow.Summary
	if err := s.db.QueryRowContext(ctx, statement, args...).Scan(
		&summary.Count,
		&summary.OpenCount,
		&summary.OriginalBytes,
		&summary.ReplyBytes,
	); err != nil {
		return flow.Summary{}, fmt.Errorf("query flow summary: %w", err)
	}

	return summary, nil
}

// buildFlowWhere constructs parameterized filters and their arguments.
func buildFlowWhere(query flow.Query) (string, []any, error) {
	clauses := make([]string, 0, 12)
	args := make([]any, 0, 12)

	add := func(clause string, values ...any) {
		clauses = append(clauses, clause)
		args = append(args, values...)
	}

	if query.Start != nil {
		add("last_seen_ns >= ?", query.Start.UTC().UnixNano())
	}
	if query.End != nil {
		add("last_seen_ns <= ?", query.End.UTC().UnixNano())
	}
	if query.Protocol != "" {
		add("protocol = ?", query.Protocol)
	}
	if query.IP != nil {
		value := query.IP.Unmap().String()
		add(
			"(original_src_ip = ? OR original_dst_ip = ? OR reply_src_ip = ? OR reply_dst_ip = ?)",
			value,
			value,
			value,
			value,
		)
	}
	if query.SourceIP != nil {
		value := query.SourceIP.Unmap().String()
		add("(original_src_ip = ? OR reply_dst_ip = ?)", value, value)
	}
	if query.DestIP != nil {
		value := query.DestIP.Unmap().String()
		add("(original_dst_ip = ? OR reply_src_ip = ?)", value, value)
	}
	if query.SourcePort != nil {
		add("(original_src_port = ? OR reply_dst_port = ?)", *query.SourcePort, *query.SourcePort)
	}
	if query.DestPort != nil {
		add("(original_dst_port = ? OR reply_src_port = ?)", *query.DestPort, *query.DestPort)
	}
	if query.Direction != "" {
		add("direction = ?", query.Direction)
	}
	if query.State != "" {
		add("state = ?", strings.ToUpper(query.State))
	}
	if query.Open != nil {
		add("open = ?", boolInt(*query.Open))
	}
	if query.Replied != nil {
		add("json_extract(payload_json, '$.replied') = ?", boolInt(*query.Replied))
	}
	if query.Preexisting != nil {
		add("json_extract(payload_json, '$.preexisting') = ?", boolInt(*query.Preexisting))
	}
	if query.Complete != nil {
		add("complete = ?", boolInt(*query.Complete))
	}
	if query.Start != nil && query.End != nil && query.End.Before(*query.Start) {
		return "", nil, errors.New("end must be after start")
	}

	if len(clauses) == 0 {
		return "", args, nil
	}

	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

// decodeCursor turns an opaque cursor into a stable secondary-sort predicate.
func decodeCursor(value string) (string, []any, error) {
	if value == "" {
		return "", nil, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", nil, fmt.Errorf("decode cursor: %w", err)
	}
	lastSeen, flowID, found := strings.Cut(string(data), "|")
	if !found || flowID == "" {
		return "", nil, errors.New("invalid cursor")
	}
	lastSeenNS, err := strconv.ParseInt(lastSeen, 10, 64)
	if err != nil {
		return "", nil, fmt.Errorf("parse cursor timestamp: %w", err)
	}

	return "(last_seen_ns < ? OR (last_seen_ns = ? AND flow_id < ?))",
		[]any{lastSeenNS, lastSeenNS, flowID},
		nil
}

// encodeCursor stores the last seen timestamp and Flow ID as a URL-safe cursor.
func encodeCursor(lastSeenNS int64, flowID string) string {
	value := strconv.FormatInt(lastSeenNS, 10) + "|" + flowID
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
