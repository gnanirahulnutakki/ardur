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
