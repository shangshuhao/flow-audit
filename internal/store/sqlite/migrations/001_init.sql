-- Initial Flow Audit schema for events, Flow snapshots, and capture gaps.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_ns INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS flow_events (
    event_id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    observed_at_ns INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flow_events_flow_time
    ON flow_events(flow_id, observed_at_ns);

CREATE INDEX IF NOT EXISTS idx_flow_events_time
    ON flow_events(observed_at_ns);

CREATE TABLE IF NOT EXISTS flows (
    flow_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    source TEXT NOT NULL,
    netns_id INTEGER NOT NULL,
    zone INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    original_src_ip TEXT NOT NULL,
    original_src_port INTEGER NOT NULL,
    original_dst_ip TEXT NOT NULL,
    original_dst_port INTEGER NOT NULL,
    reply_src_ip TEXT,
    reply_src_port INTEGER,
    reply_dst_ip TEXT,
    reply_dst_port INTEGER,
    direction TEXT NOT NULL,
    state TEXT,
    open INTEGER NOT NULL,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns INTEGER NOT NULL,
    closed_at_ns INTEGER,
    original_bytes INTEGER NOT NULL,
    reply_bytes INTEGER NOT NULL,
    complete INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_flows_active_tuple
    ON flows(
        node_id,
        source,
        netns_id,
        zone,
        protocol,
        original_src_ip,
        original_src_port,
        original_dst_ip,
        original_dst_port
    )
    WHERE open = 1;

CREATE INDEX IF NOT EXISTS idx_flows_last_seen
    ON flows(last_seen_ns);

CREATE INDEX IF NOT EXISTS idx_flows_original_src
    ON flows(original_src_ip, last_seen_ns);

CREATE INDEX IF NOT EXISTS idx_flows_original_dst
    ON flows(original_dst_ip, last_seen_ns);

CREATE INDEX IF NOT EXISTS idx_flows_reply_src
    ON flows(reply_src_ip, last_seen_ns);

CREATE INDEX IF NOT EXISTS idx_flows_reply_dst
    ON flows(reply_dst_ip, last_seen_ns);

CREATE INDEX IF NOT EXISTS idx_flows_protocol_port
    ON flows(protocol, original_dst_port, last_seen_ns);

CREATE TABLE IF NOT EXISTS capture_gaps (
    gap_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    source TEXT NOT NULL,
    started_at_ns INTEGER NOT NULL,
    ended_at_ns INTEGER,
    reason TEXT NOT NULL,
    lost_count INTEGER NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_capture_gaps_time
    ON capture_gaps(started_at_ns, ended_at_ns);
