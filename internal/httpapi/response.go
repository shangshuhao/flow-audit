package httpapi

import (
	"encoding/json"
	"net/http"
)

// writeJSON serializes a response with the standard JSON content type.
func writeJSON(w http.ResponseWriter, statusCode int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(value)
}

// writeError serializes the stable API error envelope.
func writeError(w http.ResponseWriter, statusCode int, code string, err error) {
	writeJSON(w, statusCode, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": err.Error(),
		},
	})
}
