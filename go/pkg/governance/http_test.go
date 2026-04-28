package governance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer() *httptest.Server {
	store := NewMemoryStore()
	engine := NewEngine()
	sink := NewLoggingActionSink()
	svc := NewSessionService(store, engine, sink)
	handler := NewHandler(svc)
	return httptest.NewServer(handler.Routes())
}

func postJSON(url string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return http.Post(url, "application/json", bytes.NewReader(data))
}

func deleteReq(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decodeJSON: %v", err)
	}
	return v
}

func TestFullLifecycle(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	decl := MissionDeclaration{
		ID:             "decl-1",
		SessionID:      "lifecycle-1",
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"tool-x"},
		CreatedAt:      time.Now().UTC(),
	}
	resp, err := postJSON(srv.URL+"/v1/declarations", decl)
	if err != nil {
		t.Fatalf("POST /v1/declarations error: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/declarations status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	session := decodeJSON[SessionState](t, resp)
	if session.ID != "lifecycle-1" {
		t.Errorf("session.ID = %q, want %q", session.ID, "lifecycle-1")
	}

	event := ObservedEvent{
		EventID:         "evt-1",
		SessionID:       "lifecycle-1",
		Timestamp:       time.Now().UTC(),
		Actor:           "agent-1",
		ActionClass:     "read",
		ToolName:        "tool-x",
		Target:          "/data",
		Summary:         "read data",
		SideEffectClass: "none",
		Visibility:      "full",
	}
	resp, err = postJSON(srv.URL+"/v1/events", event)
	if err != nil {
		t.Fatalf("POST /v1/events error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/events status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	decision := decodeJSON[Decision](t, resp)
	if decision.State != DecisionCompliant {
		t.Errorf("decision.State = %q, want %q", decision.State, DecisionCompliant)
	}

	resp, err = http.Get(srv.URL + "/v1/sessions/lifecycle-1")
	if err != nil {
		t.Fatalf("GET /v1/sessions/lifecycle-1 error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET session status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	got := decodeJSON[SessionState](t, resp)
	if got.Phase != PhaseActive {
		t.Errorf("phase = %q, want %q", got.Phase, PhaseActive)
	}

	resp, err = http.Get(srv.URL + "/v1/decisions/lifecycle-1")
	if err != nil {
		t.Fatalf("GET /v1/decisions/lifecycle-1 error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET decision status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	dec := decodeJSON[Decision](t, resp)
	if dec.SessionID != "lifecycle-1" {
		t.Errorf("decision.SessionID = %q, want %q", dec.SessionID, "lifecycle-1")
	}

	resp, err = deleteReq(srv.URL + "/v1/sessions/lifecycle-1")
	if err != nil {
		t.Fatalf("DELETE /v1/sessions/lifecycle-1 error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE session status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	closed := decodeJSON[SessionState](t, resp)
	if closed.Phase != PhaseClosed {
		t.Errorf("closed phase = %q, want %q", closed.Phase, PhaseClosed)
	}
}

func TestViolationDetectionE2E(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	decl := MissionDeclaration{
		ID:             "decl-v",
		SessionID:      "violation-1",
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"safe-tool"},
		CreatedAt:      time.Now().UTC(),
	}
	resp, _ := postJSON(srv.URL+"/v1/declarations", decl)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	event := ObservedEvent{
		EventID:         "evt-bad",
		SessionID:       "violation-1",
		Timestamp:       time.Now().UTC(),
		Actor:           "rogue",
		ActionClass:     "write",
		ToolName:        "unsafe-tool",
		Target:          "/secret",
		Summary:         "write to secret",
		SideEffectClass: "none",
		Visibility:      "full",
	}
	resp, _ = postJSON(srv.URL+"/v1/events", event)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("event status = %d", resp.StatusCode)
	}

	decision := decodeJSON[Decision](t, resp)
	if decision.State != DecisionViolation {
		t.Errorf("decision.State = %q, want %q", decision.State, DecisionViolation)
	}
	if len(decision.Findings) == 0 {
		t.Error("expected at least one finding")
	}
	if decision.RecommendedAction == ActionNone {
		t.Error("expected a non-none recommended action for violations")
	}
}

func TestUnknownVisibilityE2E(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	decl := MissionDeclaration{
		ID:             "decl-u",
		SessionID:      "unknown-1",
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"tool-a"},
		CreatedAt:      time.Now().UTC(),
	}
	resp, _ := postJSON(srv.URL+"/v1/declarations", decl)
	resp.Body.Close()

	event := ObservedEvent{
		EventID:         "evt-partial",
		SessionID:       "unknown-1",
		Timestamp:       time.Now().UTC(),
		Actor:           "agent",
		ActionClass:     "read",
		ToolName:        "tool-a",
		Target:          "/data",
		Summary:         "partial read",
		SideEffectClass: "none",
		Visibility:      "partial",
	}
	resp, _ = postJSON(srv.URL+"/v1/events", event)
	decision := decodeJSON[Decision](t, resp)
	if decision.State != DecisionUnknown {
		t.Errorf("decision.State = %q, want %q", decision.State, DecisionUnknown)
	}
}

func TestInvalidDeclaration400(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	bad := MissionDeclaration{ID: "", SessionID: "x"}
	resp, _ := postJSON(srv.URL+"/v1/declarations", bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()
}

func TestEventForMissingSession404(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	event := ObservedEvent{
		EventID:         "evt-1",
		SessionID:       "nonexistent",
		Timestamp:       time.Now().UTC(),
		Actor:           "agent",
		ActionClass:     "read",
		ToolName:        "tool-a",
		Target:          "/data",
		Summary:         "test",
		SideEffectClass: "none",
		Visibility:      "full",
	}
	resp, _ := postJSON(srv.URL+"/v1/events", event)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}

func TestGetNonExistentSession404(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/v1/sessions/no-such-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}

func TestGetNonExistentDecision404(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/v1/decisions/no-such-id")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}

func TestListSessionsWithPhaseFilter(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("filter-%d", i)
		decl := MissionDeclaration{
			ID:             "d-" + id,
			SessionID:      id,
			AllowedActions: []string{"read"},
			AllowedTools:   []string{"t"},
			CreatedAt:      time.Now().UTC(),
		}
		resp, _ := postJSON(srv.URL+"/v1/declarations", decl)
		resp.Body.Close()
	}

	event := ObservedEvent{
		EventID:         "e-0",
		SessionID:       "filter-0",
		Timestamp:       time.Now().UTC(),
		Actor:           "a",
		ActionClass:     "read",
		ToolName:        "t",
		Target:          "/x",
		Summary:         "s",
		SideEffectClass: "none",
		Visibility:      "full",
	}
	resp, _ := postJSON(srv.URL+"/v1/events", event)
	resp.Body.Close()

	resp, _ = http.Get(srv.URL + "/v1/sessions?phase=active")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	sessions := decodeJSON[[]SessionState](t, resp)
	if len(sessions) != 1 {
		t.Errorf("len(sessions) = %d, want 1 active", len(sessions))
	}

	resp, _ = http.Get(srv.URL + "/v1/sessions?phase=initialized")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	sessions = decodeJSON[[]SessionState](t, resp)
	if len(sessions) != 2 {
		t.Errorf("len(sessions) = %d, want 2 initialized", len(sessions))
	}

	resp, _ = http.Get(srv.URL + "/v1/sessions")
	sessions = decodeJSON[[]SessionState](t, resp)
	if len(sessions) != 3 {
		t.Errorf("len(sessions) = %d, want 3 total", len(sessions))
	}
}

func TestHealthz(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	h := decodeJSON[healthResponse](t, resp)
	if h.Status != "ok" {
		t.Errorf("health status = %q, want %q", h.Status, "ok")
	}
}

func TestReadyz(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := http.Get(srv.URL + "/readyz")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("readyz status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	h := decodeJSON[healthResponse](t, resp)
	if h.Status != "ready" {
		t.Errorf("ready status = %q, want %q", h.Status, "ready")
	}
}

func TestContentTypeEnforcement(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	body := `{"id":"x","session_id":"x","allowed_actions":["a"],"allowed_tools":["t"]}`
	resp, _ := http.Post(srv.URL+"/v1/declarations", "text/plain", strings.NewReader(body))
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnsupportedMediaType)
	}
	resp.Body.Close()
}

func TestRequestBodyTooLarge(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	huge := strings.Repeat("x", maxRequestBody+1)
	body := fmt.Sprintf(`{"id":"%s"}`, huge)
	resp, _ := http.Post(srv.URL+"/v1/declarations", "application/json", strings.NewReader(body))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()
}

func TestResponseContentType(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz error: %v", err)
	}
	defer resp.Body.Close()
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestDeleteNonExistentSession(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := deleteReq(srv.URL + "/v1/sessions/nope")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}

func TestMalformedJSON(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := http.Post(srv.URL+"/v1/declarations", "application/json", strings.NewReader("{bad json"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()
}

func TestCompliantSessionE2E(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	decl := MissionDeclaration{
		ID:             "d-compliant",
		SessionID:      "compliant-1",
		AllowedActions: []string{"read", "write"},
		AllowedTools:   []string{"editor", "viewer"},
		CreatedAt:      time.Now().UTC(),
	}
	resp, _ := postJSON(srv.URL+"/v1/declarations", decl)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	for i := 0; i < 5; i++ {
		event := ObservedEvent{
			EventID:         fmt.Sprintf("evt-%d", i),
			SessionID:       "compliant-1",
			Timestamp:       time.Now().UTC(),
			Actor:           "agent",
			ActionClass:     "read",
			ToolName:        "viewer",
			Target:          fmt.Sprintf("/file-%d", i),
			Summary:         "read file",
			SideEffectClass: "none",
			Visibility:      "full",
		}
		resp, _ = postJSON(srv.URL+"/v1/events", event)
		dec := decodeJSON[Decision](t, resp)
		if dec.State != DecisionCompliant {
			t.Errorf("event %d: state = %q, want compliant", i, dec.State)
		}
	}

	resp, _ = http.Get(srv.URL + "/v1/decisions/compliant-1")
	final := decodeJSON[Decision](t, resp)
	if final.EventsProcessed != 5 {
		t.Errorf("events_processed = %d, want 5", final.EventsProcessed)
	}
}

func TestEmptyBody(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	resp, _ := http.Post(srv.URL+"/v1/declarations", "application/json", bytes.NewReader(nil))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for empty body", resp.StatusCode, http.StatusBadRequest)
	}
	resp.Body.Close()
}

func TestCloseAlreadyClosedSessionViaHTTP(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	decl := MissionDeclaration{
		ID:             "d-close",
		SessionID:      "close-twice",
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"t"},
		CreatedAt:      time.Now().UTC(),
	}
	resp, _ := postJSON(srv.URL+"/v1/declarations", decl)
	resp.Body.Close()

	resp, _ = deleteReq(srv.URL + "/v1/sessions/close-twice")
	resp.Body.Close()

	resp, _ = deleteReq(srv.URL + "/v1/sessions/close-twice")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want %d for double close", resp.StatusCode, http.StatusConflict)
	}
	resp.Body.Close()
}

func TestDecisionBeforeAnyEvent(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	decl := MissionDeclaration{
		ID:             "d-early",
		SessionID:      "early-decision",
		AllowedActions: []string{"read"},
		AllowedTools:   []string{"t"},
		CreatedAt:      time.Now().UTC(),
	}
	resp, _ := postJSON(srv.URL+"/v1/declarations", decl)
	resp.Body.Close()

	resp, _ = http.Get(srv.URL + "/v1/decisions/early-decision")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d for no decision yet", resp.StatusCode, http.StatusNotFound)
	}
	resp.Body.Close()
}
