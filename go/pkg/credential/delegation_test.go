package credential

import (
	"strings"
	"testing"
	"time"
)

func TestEscrowRightsFirstChildIncludesReservedBudgetShareClaim(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 10
	childToken, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:       rootToken,
		PublicKey:         key.PublicKey,
		SigningKey:        key,
		ChildAgentID:      "c1",
		ChildAllowedTools: []string{"read"},
		ChildMission:      "sub",
		ChildMaxToolCalls: &childMax,
	})
	if err != nil {
		t.Fatalf("DeriveChildPassport() error: %v", err)
	}

	claims, err := VerifyPassport(childToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport() error: %v", err)
	}
	if claims.ReservedBudgetShare != 10 {
		t.Fatalf("ReservedBudgetShare = %d, want 10", claims.ReservedBudgetShare)
	}
}

func TestEscrowRightsThirdSiblingClampedByReservationPool(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 15
	childToken, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:                  rootToken,
		PublicKey:                    key.PublicKey,
		SigningKey:                   key,
		ChildAgentID:                 "c3",
		ChildAllowedTools:            []string{"read"},
		ChildMission:                 "third sibling",
		ChildMaxToolCalls:            &childMax,
		ParentReservedForDescendants: 20,
	})
	if err != nil {
		t.Fatalf("DeriveChildPassport() error: %v", err)
	}

	claims, err := VerifyPassport(childToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport() error: %v", err)
	}
	if claims.MaxToolCalls != 10 {
		t.Fatalf("MaxToolCalls = %d, want 10", claims.MaxToolCalls)
	}
	if claims.ReservedBudgetShare != 10 {
		t.Fatalf("ReservedBudgetShare = %d, want 10", claims.ReservedBudgetShare)
	}
}

func TestEscrowRightsCeilingExhaustedRejectsDelegation(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 5
	_, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:                  rootToken,
		PublicKey:                    key.PublicKey,
		SigningKey:                   key,
		ChildAgentID:                 "cN",
		ChildAllowedTools:            []string{"read"},
		ChildMission:                 "last attempt",
		ChildMaxToolCalls:            &childMax,
		ParentReservedForDescendants: 30,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "descendant-reservation pool exhausted; cannot delegate") {
		t.Fatalf("error %q does not contain descendant-reservation exhaustion", err.Error())
	}
}

func TestEscrowRightsOverAllocatedReservationRejected(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 5
	_, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:                  rootToken,
		PublicKey:                    key.PublicKey,
		SigningKey:                   key,
		ChildAgentID:                 "bad",
		ChildAllowedTools:            []string{"read"},
		ChildMission:                 "bad reservation report",
		ChildMaxToolCalls:            &childMax,
		ParentReservedForDescendants: 31,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds parent ceiling") {
		t.Fatalf("error %q does not contain exceeds parent ceiling", err.Error())
	}
}

func TestEscrowRightsNegativeReservationRejected(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 5
	_, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:                  rootToken,
		PublicKey:                    key.PublicKey,
		SigningKey:                   key,
		ChildAgentID:                 "bad",
		ChildAllowedTools:            []string{"read"},
		ChildMission:                 "bad",
		ChildMaxToolCalls:            &childMax,
		ParentReservedForDescendants: -1,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "parent_reserved_for_descendants must be non-negative") {
		t.Fatalf("error %q does not contain non-negative validation", err.Error())
	}
}

func TestEscrowRightsDefaultZeroReservationPreservesBackCompat(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 10
	childToken, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:       rootToken,
		PublicKey:         key.PublicKey,
		SigningKey:        key,
		ChildAgentID:      "back-compat",
		ChildAllowedTools: []string{"read"},
		ChildMission:      "legacy caller",
		ChildMaxToolCalls: &childMax,
	})
	if err != nil {
		t.Fatalf("DeriveChildPassport() error: %v", err)
	}

	claims, err := VerifyPassport(childToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport() error: %v", err)
	}
	if claims.MaxToolCalls != 10 {
		t.Fatalf("MaxToolCalls = %d, want 10", claims.MaxToolCalls)
	}
	if claims.ReservedBudgetShare != 10 {
		t.Fatalf("ReservedBudgetShare = %d, want 10", claims.ReservedBudgetShare)
	}
}

func TestDeriveChildPassportCopiesAncestorBudgetSnapshotIntoChain(t *testing.T) {
	key := testSigningKey(t)
	rootToken := issueEscrowRoot(t, key, 30)

	childMax := 10
	childToken, err := DeriveChildPassport(DeriveChildOptions{
		ParentToken:       rootToken,
		PublicKey:         key.PublicKey,
		SigningKey:        key,
		ChildAgentID:      "audit-child",
		ChildAllowedTools: []string{"read"},
		ChildMission:      "audit child",
		ChildMaxToolCalls: &childMax,
	})
	if err != nil {
		t.Fatalf("DeriveChildPassport() error: %v", err)
	}

	claims, err := VerifyPassport(childToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport() error: %v", err)
	}
	if len(claims.DelegationChain) != 1 {
		t.Fatalf("DelegationChain len = %d, want 1", len(claims.DelegationChain))
	}
	if claims.DelegationChain[0].MaxToolCalls != 30 {
		t.Fatalf("chain[0].MaxToolCalls = %d, want 30", claims.DelegationChain[0].MaxToolCalls)
	}
}

func issueEscrowRoot(t *testing.T, key *SigningKey, ceiling int) string {
	t.Helper()
	root, err := IssuePassport(MissionPassport{
		AgentID:            "root",
		Mission:            "coordinate fan-out",
		AllowedTools:       []string{"read", "write"},
		MaxToolCalls:       ceiling,
		MaxDurationSeconds: 600,
		DelegationAllowed:  true,
		MaxDelegationDepth: 3,
	}, key, &IssuePassportOptions{
		TTL: 600 * time.Second,
	})
	if err != nil {
		t.Fatalf("IssuePassport() error: %v", err)
	}
	return root
}

// TestVerifyPassportFutureIatRejected pins FIX-R5-H3 (round-5 audit,
// 2026-04-29). Round-3's bounded-iat-skew gate landed on the SD-JWT-VC
// verifier; round-4 audit found this VerifyPassport path missed it.
// Round-5 added the gate at delegation.go:213-228; this test guards
// against a revert that would silently re-open the future-iat bypass.
func TestVerifyPassportFutureIatRejected(t *testing.T) {
	key := testSigningKey(t)
	// Mint a passport with iat one hour in the future — well beyond
	// the 30s clock-drift tolerance the verifier allows.
	farFuture := time.Now().Add(1 * time.Hour)
	tok, err := IssuePassport(MissionPassport{
		AgentID:            "root-far-future",
		Mission:            "iat-skew test",
		AllowedTools:       []string{"read"},
		MaxToolCalls:       5,
		MaxDurationSeconds: 600,
	}, key, &IssuePassportOptions{
		TTL: 600 * time.Second,
		Now: farFuture,
	})
	if err != nil {
		t.Fatalf("IssuePassport(): %v", err)
	}

	_, err = VerifyPassport(tok, key.PublicKey)
	if err == nil {
		t.Fatal("VerifyPassport accepted a passport with iat far in the future; FIX-R5-H3 must reject")
	}
	if !strings.Contains(err.Error(), "iat lies more than") {
		t.Errorf("error = %q, want it to contain 'iat lies more than'", err.Error())
	}
}

// TestVerifyPassportIatWithinSkewWindowAccepted complements the
// rejection test: an iat 15s in the future (within 30s tolerance)
// must still be accepted, so the fix doesn't false-positive on
// legitimate cross-node clock drift.
func TestVerifyPassportIatWithinSkewWindowAccepted(t *testing.T) {
	key := testSigningKey(t)
	slightFuture := time.Now().Add(15 * time.Second)
	tok, err := IssuePassport(MissionPassport{
		AgentID:            "root-slight-future",
		Mission:            "iat-window-accept test",
		AllowedTools:       []string{"read"},
		MaxToolCalls:       5,
		MaxDurationSeconds: 600,
	}, key, &IssuePassportOptions{
		TTL: 600 * time.Second,
		Now: slightFuture,
	})
	if err != nil {
		t.Fatalf("IssuePassport(): %v", err)
	}
	if _, err := VerifyPassport(tok, key.PublicKey); err != nil {
		t.Errorf("passport with iat=now+15s rejected: %v", err)
	}
}
