package httpapi

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"flowaudit/internal/flow"
)

// authMiddleware protects API routes with an optional constant-time bearer check.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.authToken == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, prefix) ||
			subtle.ConstantTimeCompare(
				[]byte(strings.TrimPrefix(header, prefix)),
				[]byte(s.authToken),
			) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", errors.New("valid bearer token is required"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware propagates or generates a request correlation ID.
func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			generated, err := flow.NewEventID()
			if err == nil {
				requestID = generated
			}
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

// recoverMiddleware converts handler panics into JSON server errors.
func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("HTTP handler panic", "panic", recovered, "path", r.URL.Path)
				writeError(w, http.StatusInternalServerError, "internal_error", errors.New("internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
