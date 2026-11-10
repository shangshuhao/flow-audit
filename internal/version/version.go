// Package version exposes build metadata populated by the Go linker.
package version

// Values are overridden with -ldflags at release time.
var (
	Version   = "0.1.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)
