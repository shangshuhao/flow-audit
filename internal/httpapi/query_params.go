package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"flowaudit/internal/flow"
)

// parseQuery validates HTTP filters and converts them into a domain query.
func parseQuery(r *http.Request) (flow.Query, error) {
	values := r.URL.Query()
	query := flow.Query{
		Protocol:  flow.Protocol(strings.ToLower(strings.TrimSpace(values.Get("protocol")))),
		Direction: flow.Direction(strings.ToLower(strings.TrimSpace(values.Get("direction")))),
		State:     strings.TrimSpace(values.Get("state")),
		Cursor:    values.Get("cursor"),
	}

	start, end, err := parseTimeRange(r)
	if err != nil {
		return flow.Query{}, err
	}
	query.Start = start
	query.End = end

	if query.Protocol != "" && query.Protocol != flow.ProtocolTCP && query.Protocol != flow.ProtocolUDP {
		return flow.Query{}, fmt.Errorf("unsupported protocol %q", query.Protocol)
	}
	if query.Direction != "" && !query.Direction.Valid() {
		return flow.Query{}, fmt.Errorf("unsupported direction %q", query.Direction)
	}

	query.IP, err = optionalIP(values.Get("ip"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("ip: %w", err)
	}
	query.SourceIP, err = optionalIP(values.Get("src_ip"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("src_ip: %w", err)
	}
	query.DestIP, err = optionalIP(values.Get("dst_ip"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("dst_ip: %w", err)
	}
	query.SourcePort, err = optionalPort(values.Get("src_port"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("src_port: %w", err)
	}
	query.DestPort, err = optionalPort(values.Get("dst_port"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("dst_port: %w", err)
	}
	query.Open, err = optionalBool(values.Get("open"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("open: %w", err)
	}
	query.Replied, err = optionalBool(values.Get("replied"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("replied: %w", err)
	}
	query.Preexisting, err = optionalBool(values.Get("preexisting"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("preexisting: %w", err)
	}
	query.Complete, err = optionalBool(values.Get("complete"))
	if err != nil {
		return flow.Query{}, fmt.Errorf("complete: %w", err)
	}
	if rawLimit := strings.TrimSpace(values.Get("limit")); rawLimit != "" {
		query.Limit, err = strconv.Atoi(rawLimit)
		if err != nil || query.Limit <= 0 {
			return flow.Query{}, errors.New("limit must be a positive integer")
		}
	}

	return query, nil
}

// parseTimeRange parses an RFC3339 window and defaults the end to now.
func parseTimeRange(r *http.Request) (*time.Time, *time.Time, error) {
	values := r.URL.Query()
	start, err := optionalTime(values.Get("start"))
	if err != nil {
		return nil, nil, fmt.Errorf("start: %w", err)
	}
	end, err := optionalTime(values.Get("end"))
	if err != nil {
		return nil, nil, fmt.Errorf("end: %w", err)
	}
	if end == nil {
		value := time.Now().UTC()
		end = &value
	}
	if start != nil && end.Before(*start) {
		return nil, nil, errors.New("end must be after start")
	}

	return start, end, nil
}

// optionalTime parses a required RFC3339 value only when it is non-empty.
func optionalTime(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("parse RFC3339 time: %w", err)
	}
	parsed = parsed.UTC()

	return &parsed, nil
}

// optionalIP parses a canonical IPv4 or IPv6 address when provided.
func optionalIP(value string) (*netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := netip.ParseAddr(value)
	if err != nil {
		return nil, fmt.Errorf("parse IP address: %w", err)
	}
	parsed = parsed.Unmap()

	return &parsed, nil
}

// optionalPort parses a valid 16-bit port when provided.
func optionalPort(value string) (*uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse port: %w", err)
	}
	result := uint16(parsed)

	return &result, nil
}

// optionalBool parses a boolean filter while preserving an absent value.
func optionalBool(value string) (*bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return nil, fmt.Errorf("parse boolean: %w", err)
	}

	return &parsed, nil
}
