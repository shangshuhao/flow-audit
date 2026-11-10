package httpapi

import (
	"io/fs"
	"net/http"
	"strings"

	"flowaudit/web"
)

// handleUI serves the embedded single-page interface and its assets.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	switch path {
	case "index.html", "app.js", "style.css":
	default:
		http.NotFound(w, r)
		return
	}

	data, err := fs.ReadFile(web.FS, path)
	if err != nil {
		s.logger.Error("read embedded UI file failed", "path", path, "error", err)
		http.Error(w, "UI asset unavailable", http.StatusInternalServerError)
		return
	}

	switch path {
	case "app.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case "style.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	_, _ = w.Write(data)
}
