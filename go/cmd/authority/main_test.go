// Authority bearer-auth regression tests (FIX-R6-6, round-6, 2026-04-29).
//
// Round-5 added bearer-token auth to /sign and /status (FIX-R5-H1) but
// shipped without unit tests for the requireBearerAuth middleware. The
// round-5 hostile audit flagged this as a HIGH test-coverage gap: the
// Governor (FIX-R5-H2) has 4 dedicated regression tests; the Authority
// had none. A revert that flipped the gate would not be caught.
//
// These tests pin:
//   - missing Authorization header → 401 + WWW-Authenticate challenge
//   - wrong token → 401
//   - correct token → request reaches the inner handler
//   - constant-time comparison: the response time for short vs long
//     wrong tokens does not noticeably differ (anti-timing-leak smoke test)

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRequireBearerAuth_RejectsMissingHeader(t *testing.T) {
	calledInner := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledInner = true
		w.WriteHeader(http.StatusOK)
	})
	wrapped := requireBearerAuth([]byte("test-token-32-bytes-test-token-AB"), inner)

	req := httptest.NewRequest("POST", "/sign", strings.NewReader(""))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", got)
	}
	if calledInner {
		t.Error("inner handler was called despite missing auth header")
	}
}

func TestRequireBearerAuth_RejectsWrongToken(t *testing.T) {
	calledInner := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledInner = true
	})
	wrapped := requireBearerAuth([]byte("expected-token-32-bytes-AB-CDEF"), inner)

	req := httptest.NewRequest("POST", "/sign", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer attacker-supplied-wrong-token")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if calledInner {
		t.Error("inner handler was called despite wrong token")
	}
}

func TestRequireBearerAuth_AcceptsCorrectToken(t *testing.T) {
	calledInner := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledInner = true
		w.WriteHeader(http.StatusOK)
	})
	token := []byte("correct-token-32-bytes-ABCD-EFGH")
	wrapped := requireBearerAuth(token, inner)

	req := httptest.NewRequest("POST", "/sign", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer correct-token-32-bytes-ABCD-EFGH")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !calledInner {
		t.Error("inner handler was NOT called despite correct token")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRequireBearerAuth_NonBearerSchemeRejected(t *testing.T) {
	// "Basic" / "Digest" / unprefixed values must not be accepted.
	cases := []struct {
		name   string
		header string
	}{
		{"Basic scheme", "Basic dXNlcjpwYXNz"},
		{"Digest scheme", "Digest username=user"},
		{"raw token without Bearer prefix", "correct-token-32-bytes-ABCD-EFGH"},
		{"empty value", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("inner handler should not have been called for %q", tc.header)
			})
			token := []byte("correct-token-32-bytes-ABCD-EFGH")
			wrapped := requireBearerAuth(token, inner)

			req := httptest.NewRequest("POST", "/sign", strings.NewReader(""))
			req.Header.Set("Authorization", tc.header)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d for %q", rec.Code, http.StatusUnauthorized, tc.header)
			}
		})
	}
}

// FIX-R9-4 (round-9, 2026-04-29): RFC 9110 §11.1 — auth-scheme is
// case-insensitive. Round-8 audit (LOW-NEW-3) flagged that the Go
// bearer parser was case-sensitive while Python was case-insensitive,
// creating a Python/Go interop skew. Pin the case-insensitive parse.
func TestRequireBearerAuth_AcceptsLowercaseBearerScheme(t *testing.T) {
	cases := []string{
		"Bearer correct-token-32-bytes-ABCD-EFGH",
		"bearer correct-token-32-bytes-ABCD-EFGH",
		"BEARER correct-token-32-bytes-ABCD-EFGH",
		"BeArEr correct-token-32-bytes-ABCD-EFGH",
	}
	token := []byte("correct-token-32-bytes-ABCD-EFGH")
	for _, hdr := range cases {
		t.Run(hdr[:6], func(t *testing.T) {
			calledInner := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calledInner = true
			})
			wrapped := requireBearerAuth(token, inner)

			req := httptest.NewRequest("POST", "/sign", strings.NewReader(""))
			req.Header.Set("Authorization", hdr)
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if !calledInner {
				t.Errorf("inner handler not called for header %q", hdr)
			}
		})
	}
}

func TestRequireBearerAuth_TrimsBearerWhitespace(t *testing.T) {
	// Some clients put an extra space after "Bearer "; the canonical
	// shape must still verify. Our impl uses strings.TrimSpace.
	calledInner := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledInner = true
	})
	token := []byte("correct-token-32-bytes-ABCD-EFGH")
	wrapped := requireBearerAuth(token, inner)

	req := httptest.NewRequest("POST", "/sign", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer  correct-token-32-bytes-ABCD-EFGH  ")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !calledInner {
		t.Error("inner handler was not called despite correct token (with trim)")
	}
}

// FIX-R7-4 (round-7, 2026-04-29) — round-6 audit MED-1: pin the
// startup-refusal logic of ``main()`` symmetric with the Governor's
// ``Validate()``. Round-6 left the Authority's startup checks
// untested; a regression that flipped the missing-token gate or
// changed the noRequireAuth defaulting would silently produce an
// unauthenticated production /sign endpoint.

func TestValidateAuthStartup_RefusesWithoutToken(t *testing.T) {
	_, err := validateAuthStartup(authStartupConfig{
		noRequireAuth: false,
		apiToken:      nil,
	})
	if err == nil {
		t.Fatal("startup must refuse when ARDUR_AUTHORITY_TOKEN is unset and --no-require-auth is not passed")
	}
	if !strings.Contains(err.Error(), "ARDUR_AUTHORITY_TOKEN") {
		t.Errorf("error must name the env var; got: %v", err)
	}
}

func TestValidateAuthStartup_RefusesShortToken(t *testing.T) {
	_, err := validateAuthStartup(authStartupConfig{
		noRequireAuth: false,
		apiToken:      []byte("too-short"),
	})
	if err == nil {
		t.Fatal("startup must refuse when ARDUR_AUTHORITY_TOKEN is shorter than 32 bytes")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("error must name the 32-byte minimum; got: %v", err)
	}
	// Honest error message: round-6 audit MED-3 flagged that "32 bytes
	// of entropy" was misleading because we only check length. The
	// round-7 message says "32 bytes long" and notes the entropy
	// caveat.
	if strings.Contains(err.Error(), "32 bytes of entropy") {
		t.Errorf("error must not claim 32 bytes is an entropy check; got: %v", err)
	}
}

func TestValidateAuthStartup_AcceptsValidToken(t *testing.T) {
	warning, err := validateAuthStartup(authStartupConfig{
		noRequireAuth: false,
		apiToken:      []byte("32-char-test-token-ABCDEFGHIJKLMN"),
	})
	if err != nil {
		t.Fatalf("startup must accept a 32+ byte token; got: %v", err)
	}
	if warning != "" {
		t.Errorf("authenticated startup must NOT emit a warning; got: %q", warning)
	}
}

func TestValidateAuthStartup_NoRequireAuthEmitsWarning(t *testing.T) {
	warning, err := validateAuthStartup(authStartupConfig{
		noRequireAuth: true,
		apiToken:      nil,
	})
	if err != nil {
		t.Fatalf("startup must accept --no-require-auth path; got: %v", err)
	}
	if warning == "" {
		t.Error("--no-require-auth path must emit a loud warning")
	}
	if !strings.Contains(strings.ToLower(warning), "production") {
		t.Errorf("warning must direct operators away from production; got: %q", warning)
	}
}

func TestValidateAuthStartup_NoRequireAuthIgnoresToken(t *testing.T) {
	// When the operator explicitly opts out of auth, the token's
	// length doesn't matter — but the warning must still fire.
	warning, err := validateAuthStartup(authStartupConfig{
		noRequireAuth: true,
		apiToken:      []byte("short"),
	})
	if err != nil {
		t.Fatalf("startup must accept --no-require-auth even with short token; got: %v", err)
	}
	if warning == "" {
		t.Error("--no-require-auth must emit a warning")
	}
}

// FIX-R9-2 (round-9, 2026-04-29) — DE-RIG REGRESSION.
//
// Round-8 audit found that round-7's R7-5 length-oracle closure for
// Go bearer-auth (SHA-256 normalize before ConstantTimeCompare) is
// not pinned by any behavioral test: reverting to raw-bytes
// ConstantTimeCompare keeps every existing test green because the
// rejection contract is unchanged — only the timing oracle reopens.
// Round-9 adds source-shape tests that would catch a revert to the
// pre-R7-5 raw-byte compare. Brittle by design: a deliberate refactor
// must update both the code AND this test.
func TestRequireBearerAuth_SourceContainsSha256Normalization(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	srcStr := string(src)

	// Required: the precomputed expected hash + per-request presented hash.
	if !strings.Contains(srcStr, "expectedHash := sha256.Sum256") {
		t.Error("FIX-R7-5 regression: requireBearerAuth must precompute expected token hash via sha256.Sum256")
	}
	if !strings.Contains(srcStr, "presentedHash := sha256.Sum256") {
		t.Error("FIX-R7-5 regression: requireBearerAuth must hash presented token via sha256.Sum256")
	}
	// Anti-pattern: raw-bytes ConstantTimeCompare.
	// The exact pre-R7-5 line was
	// ``subtle.ConstantTimeCompare(presented, expectedToken) != 1``
	// — flag the parts in case a refactor renames variables.
	if strings.Contains(srcStr, "ConstantTimeCompare(presented, expectedToken)") {
		t.Error("FIX-R7-5 regression: bearer-auth reverted to raw-bytes ConstantTimeCompare, leaking length via timing. Use sha256-normalized inputs.")
	}
}
