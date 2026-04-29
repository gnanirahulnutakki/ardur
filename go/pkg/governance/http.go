package governance

import (
	"crypto/sha256"
	"crypto/subtle"
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

	// FIX-R5-H2 (2026-04-29) — bearer-token auth on /v1/*. When
	// authToken is non-nil and non-empty, the auth middleware is
	// active. NewHandler keeps it nil for back-compat; NewHandlerWithAuth
	// is the production constructor.
	authToken []byte
}

// NewHandler builds a handler with NO authentication on /v1/* routes.
//
// SECURITY-RELEVANT (FIX-R6-7, round-6, 2026-04-29): this constructor
// is a foot-gun. Round-5 audit flagged that callers who pick this
// instead of NewHandlerWithAuth get unauthenticated control-plane
// endpoints with no warning logged. Production code MUST use
// NewHandlerWithAuth; this constructor is retained ONLY for tests
// and explicit local-dev opt-out via cmd/governor's
// ARDUR_GOVERNOR_NO_REQUIRE_AUTH env flag. A loud warning is emitted
// on construction so accidental use shows up in deployment logs.
func NewHandler(service *SessionService) *Handler {
	slog.Warn(
		"governance.NewHandler called WITHOUT bearer-token auth — every " +
			"/v1/* route accepts unauthenticated requests. Production " +
			"deployments MUST use NewHandlerWithAuth(service, token). " +
			"This is a hard foot-gun: only use NewHandler for tests or " +
			"explicit local-dev opt-out via ARDUR_GOVERNOR_NO_REQUIRE_AUTH.")
	return &Handler{
		service: service,
		logger:  slog.Default(),
	}
}

// NewHandlerWithAuth builds a handler that requires a bearer token on
// every /v1/* route. The token is compared in constant time. Public
// routes (/healthz, /readyz) remain unauthenticated for liveness/
// readiness probes. Pass an empty byteslice ONLY in tests that
// explicitly opt out — production code MUST pass a real token.
func NewHandlerWithAuth(service *SessionService, authToken []byte) *Handler {
	return &Handler{
		service:   service,
		logger:    slog.Default(),
		authToken: authToken,
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

	// /v1/* endpoints require bearer-token auth when h.authToken is
	// configured (FIX-R5-H2 from round-4 audit). /healthz and /readyz
	// stay unauthenticated for K8s liveness/readiness probes.
	requireAuth := func(next http.HandlerFunc) http.HandlerFunc {
		if len(h.authToken) == 0 {
			// Auth is unconfigured — handler runs raw. This path is
			// reachable via NewHandler (back-compat for tests). Production
			// code uses NewHandlerWithAuth and sets a token; main.go in
			// cmd/governor refuses to start without one.
			return next
		}
		return h.bearerAuth(next)
	}
	mux.HandleFunc("POST /v1/declarations", requireAuth(h.createDeclaration))
	mux.HandleFunc("POST /v1/events", requireAuth(h.ingestEvent))
	mux.HandleFunc("GET /v1/sessions", requireAuth(h.listSessions))
	mux.HandleFunc("GET /v1/sessions/{id}", requireAuth(h.getSession))
	mux.HandleFunc("DELETE /v1/sessions/{id}", requireAuth(h.closeSession))
	mux.HandleFunc("GET /v1/decisions/{id}", requireAuth(h.getDecision))
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)

	return h.recovery(h.logging(h.contentType(mux)))
}

// bearerAuth wraps a handler with a length-independent bearer-token
// check. 401 fall-through on missing or mismatched Authorization
// header. Round-7 hardening (FIX-R7-5, 2026-04-29) hashes both
// presented and expected tokens through SHA-256 before the
// constant-time compare, so the response time does not leak the
// expected token's length to a remote attacker. (subtle.ConstantTimeCompare
// short-circuits on length mismatch by stdlib design.)
func (h *Handler) bearerAuth(next http.HandlerFunc) http.HandlerFunc {
	expectedHash := sha256.Sum256(h.authToken)
	return func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		// FIX-R9-4 (round-9, 2026-04-29): RFC 9110 §11.1 — auth-scheme
		// is case-insensitive. Match Python's parser (which uses
		// .lower().startswith()).
		if len(hdr) < len("Bearer ") || !strings.EqualFold(hdr[:len("Bearer ")], "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ardur-governor"`)
			writeJSON(w, http.StatusUnauthorized,
				apiError{Error: "Authorization: Bearer <token> required"})
			return
		}
		presented := []byte(strings.TrimSpace(hdr[len("Bearer "):]))
		presentedHash := sha256.Sum256(presented)
		if subtle.ConstantTimeCompare(presentedHash[:], expectedHash[:]) != 1 {
			writeJSON(w, http.StatusUnauthorized,
				apiError{Error: "invalid bearer token"})
			return
		}
		next(w, r)
	}
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
