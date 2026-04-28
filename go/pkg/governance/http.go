package governance

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const maxRequestBody = 1 << 20 // 1 MB

type Handler struct {
	service *SessionService
	logger  *slog.Logger
}

func NewHandler(service *SessionService) *Handler {
	return &Handler{
		service: service,
		logger:  slog.Default(),
	}
}

// --- JSON request/response envelopes ---

type apiError struct {
	Error string `json:"error"`
}

type healthResponse struct {
	Status string `json:"status"`
}

// --- Router ---

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/declarations", h.createDeclaration)
	mux.HandleFunc("POST /v1/events", h.ingestEvent)
	mux.HandleFunc("GET /v1/sessions", h.listSessions)
	mux.HandleFunc("GET /v1/sessions/{id}", h.getSession)
	mux.HandleFunc("DELETE /v1/sessions/{id}", h.closeSession)
	mux.HandleFunc("GET /v1/decisions/{id}", h.getDecision)
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)

	return h.recovery(h.logging(h.contentType(mux)))
}

// --- Handlers ---

func (h *Handler) createDeclaration(w http.ResponseWriter, r *http.Request) {
	var decl MissionDeclaration
	if err := readJSON(r, &decl); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	session, err := h.service.CreateSession(r.Context(), &decl)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, session)
}

func (h *Handler) ingestEvent(w http.ResponseWriter, r *http.Request) {
	var event ObservedEvent
	if err := readJSON(r, &event); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}

	decision, err := h.service.IngestEvent(r.Context(), &event)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, decision)
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	var phaseFilter *SessionPhase
	if raw := r.URL.Query().Get("phase"); raw != "" {
		p := SessionPhase(raw)
		phaseFilter = &p
	}

	sessions, err := h.service.ListSessions(r.Context(), phaseFilter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, sessions)
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	session, err := h.service.GetSession(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, session)
}

func (h *Handler) getDecision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	decision, err := h.service.GetDecision(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, decision)
}

func (h *Handler) closeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	session, err := h.service.CloseSession(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, session)
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	_, err := h.service.ListSessions(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, healthResponse{Status: "not ready"})
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{Status: "ready"})
}

// --- Middleware ---

func (h *Handler) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		h.logger.Info("request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.status),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

func (h *Handler) recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				h.logger.Error("panic recovered",
					slog.String("path", r.URL.Path),
					slog.Any("error", rec),
				)
				writeJSON(w, http.StatusInternalServerError, apiError{Error: "internal server error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) contentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, apiError{Error: "Content-Type must be application/json"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Helpers ---

func (h *Handler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case IsSessionNotFound(err):
		writeJSON(w, http.StatusNotFound, apiError{Error: err.Error()})
	case IsInvalidDeclaration(err), IsInvalidEvent(err):
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
	case IsSessionClosed(err):
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
	}
}

func readJSON(r *http.Request, dst any) error {
	body := http.MaxBytesReader(nil, r.Body, maxRequestBody)
	defer body.Close()

	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			return fmt.Errorf("request body too large (max %d bytes)", maxRequestBody)
		}
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to write response", slog.String("error", err.Error()))
	}
}

type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
