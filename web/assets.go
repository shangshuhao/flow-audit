// Package web embeds the dependency-free Flow Audit user interface.
package web

import "embed"

// FS contains the embedded read-only user interface.
//
//go:embed index.html app.js style.css
var FS embed.FS
