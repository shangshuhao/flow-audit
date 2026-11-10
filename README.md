# Flow Audit

Flow Audit is an audit-first connection observability project for Linux. The
first data source is Netfilter conntrack. It converts source-specific connection
tracking events into a stable `Flow` model, persists event history and Flow
snapshots, and exposes a read-only query API and minimal web UI.

## Features

- Native Go Netfilter conntrack collection without cgo
- NEW, UPDATE, DESTROY and existing-connection import events
- IPv4, IPv6, TCP and UDP normalization
- Bidirectional original/reply tuples and NAT status flags
- Open Flow restoration after process restart
- SQLite event history and Flow snapshots
- Cursor-based filtering and JSONL/CSV evidence export
- Explicit capture gaps for dropped or unavailable observation windows
- Embedded web UI with no frontend build step
- Read-only API, health checks and Prometheus text metrics

## Quick start

Linux collection:

```sh
go build -o flowaudit ./cmd/flowaudit
sudo ./flowaudit run -config config.example.yaml
```

Open `http://127.0.0.1:8080`.

Without a Linux conntrack source, the existing database and UI can be served:

```sh
./flowaudit serve
```

## Commands

```text
flowaudit run
flowaudit serve
flowaudit doctor
flowaudit version
```

## Requirements

- Linux for conntrack collection
- Netfilter conntrack and Netlink access
- Root or an appropriate network administration capability
- Go 1.22 or newer to build

`CGO_ENABLED=0` is supported. SQLite is provided by a pure-Go driver.

## Scope

This version captures connection-level audit metadata. It does not capture packet
payloads, HTTP paths, request bodies, DNS answers or application traces.

`conntrack` and `Flow` are intentionally separate concepts:

```text
Conntrack source -> normalized FlowEvent -> materialized Flow
```

## Open-source notice

The implementation is a clean-room product design based on public Linux APIs and
public dependency interfaces. Before publishing, confirm ownership and
confidentiality requirements for any related work and review dependency licenses.
