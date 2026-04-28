package governance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/gnanirahulnutakki/ardur/go/pkg/credential"
)

func TestAuditChainBudgetPassesForDerivedChild(t *testing.T) {
	key := governanceSigningKey(t)
	rootToken := governanceRootToken(t, key, 30)

	childMax := 10
	childToken, err := credential.DeriveChildPassport(credential.DeriveChildOptions{
		ParentToken:       rootToken,
		PublicKey:         key.PublicKey,
		SigningKey:        key,
		ChildAgentID:      "leaf",
		ChildAllowedTools: []string{"read"},
		ChildMission:      "leaf mission",
		ChildMaxToolCalls: &childMax,
	})
	if err != nil {
		t.Fatalf("DeriveChildPassport() error: %v", err)
	}

	result, err := AuditChainBudget(rootToken, childToken, key.PublicKey)
	if err != nil {
		t.Fatalf("AuditChainBudget() error: %v", err)
	}
	if result.Violation {
		t.Fatalf("Violation = true, want false: %+v", result)
	}
	if result.DiscoveredReservedRoot != 10 {
		t.Fatalf("DiscoveredReservedRoot = %d, want 10", result.DiscoveredReservedRoot)
	}
}

func TestAuditChainBudgetFlagsRootOverAllocation(t *testing.T) {
	key := governanceSigningKey(t)
	rootToken := governanceRootToken(t, key, 30)
	rootClaims, err := credential.VerifyPassport(rootToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport(root) error: %v", err)
	}

	now := time.Now()
	leafToken, err := credential.SignPassportClaims(credential.PassportClaims{
		Issuer:              rootClaims.Issuer,
		Subject:             "forged-leaf",
		Audience:            rootClaims.Audience,
		IssuedAt:            now.Unix(),
		NotBefore:           now.Unix(),
		ExpiresAt:           now.Add(5 * time.Minute).Unix(),
		JWTID:               "forged-leaf-jti",
		MissionID:           "forged-leaf-jti",
		Mission:             "forged branch",
		AllowedTools:        []string{"read"},
		MaxToolCalls:        35,
		MaxDurationSeconds:  300,
		DelegationAllowed:   false,
		MaxDelegationDepth:  0,
		ParentJTI:           rootClaims.JWTID,
		ParentTokenHash:     hashTokenForTest(rootToken),
		ReservedBudgetShare: 35,
		DelegationChain: []credential.DelegationChainLink{{
			JTI:          rootClaims.JWTID,
			MaxToolCalls: rootClaims.MaxToolCalls,
		}},
	}, key)
	if err != nil {
		t.Fatalf("SignPassportClaims() error: %v", err)
	}

	result, err := AuditChainBudget(rootToken, leafToken, key.PublicKey)
	if err != nil {
		t.Fatalf("AuditChainBudget() error: %v", err)
	}
	if !result.Violation {
		t.Fatalf("Violation = false, want true: %+v", result)
	}
	if result.DiscoveredReservedRoot != 35 {
		t.Fatalf("DiscoveredReservedRoot = %d, want 35", result.DiscoveredReservedRoot)
	}
}

func TestAuditChainBudgetRejectsLeafThatDoesNotReachRoot(t *testing.T) {
	key := governanceSigningKey(t)
	rootToken := governanceRootToken(t, key, 30)

	now := time.Now()
	leafToken, err := credential.SignPassportClaims(credential.PassportClaims{
		Issuer:              "vibap-governance-proxy",
		Subject:             "detached-leaf",
		Audience:            "vibap-proxy",
		IssuedAt:            now.Unix(),
		NotBefore:           now.Unix(),
		ExpiresAt:           now.Add(5 * time.Minute).Unix(),
		JWTID:               "detached-leaf-jti",
		MissionID:           "detached-leaf-jti",
		Mission:             "detached branch",
		AllowedTools:        []string{"read"},
		MaxToolCalls:        10,
		MaxDurationSeconds:  300,
		DelegationAllowed:   false,
		MaxDelegationDepth:  0,
		ParentJTI:           "unknown-parent",
		ParentTokenHash:     "abc123",
		ReservedBudgetShare: 10,
		DelegationChain: []credential.DelegationChainLink{{
			JTI:          "unknown-parent",
			MaxToolCalls: 50,
		}},
	}, key)
	if err != nil {
		t.Fatalf("SignPassportClaims() error: %v", err)
	}

	if _, err := AuditChainBudget(rootToken, leafToken, key.PublicKey); err == nil {
		t.Fatal("expected chain reachability error, got nil")
	}
}

func TestAuditChainBudgetRejectsRootLookingLeafWithSpuriousDelegationChain(t *testing.T) {
	key := governanceSigningKey(t)
	rootToken := governanceRootToken(t, key, 30)

	now := time.Now()
	leafToken, err := credential.SignPassportClaims(credential.PassportClaims{
		Issuer:             "vibap-governance-proxy",
		Subject:            "root-looking-leaf",
		Audience:           "vibap-proxy",
		IssuedAt:           now.Unix(),
		NotBefore:          now.Unix(),
		ExpiresAt:          now.Add(5 * time.Minute).Unix(),
		JWTID:              "root-looking-leaf-jti",
		MissionID:          "root-looking-leaf-jti",
		Mission:            "spurious root-like branch",
		AllowedTools:       []string{"read"},
		MaxToolCalls:       10,
		MaxDurationSeconds: 300,
		DelegationAllowed:  false,
		MaxDelegationDepth: 0,
		DelegationChain: []credential.DelegationChainLink{{
			JTI:          "ghost-parent",
			MaxToolCalls: 50,
		}},
	}, key)
	if err != nil {
		t.Fatalf("SignPassportClaims() error: %v", err)
	}

	_, err = AuditChainBudget(rootToken, leafToken, key.PublicKey)
	if err == nil {
		t.Fatal("expected delegation chain validation error, got nil")
	}
	if got, want := err.Error(), "verifying leaf token: root passport must not include delegation_chain"; got != want {
		t.Fatalf("AuditChainBudget() error = %q, want %q", got, want)
	}
}

func TestAuditChainBudgetRejectsUnsignedSiblingBranchesEmbeddedInChain(t *testing.T) {
	key := governanceSigningKey(t)
	rootToken := governanceRootToken(t, key, 30)
	rootClaims, err := credential.VerifyPassport(rootToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport(root) error: %v", err)
	}

	now := time.Now()
	leafToken, err := credential.SignPassportClaims(credential.PassportClaims{
		Issuer:              rootClaims.Issuer,
		Subject:             "leaf-with-siblings",
		Audience:            rootClaims.Audience,
		IssuedAt:            now.Unix(),
		NotBefore:           now.Unix(),
		ExpiresAt:           now.Add(5 * time.Minute).Unix(),
		JWTID:               "leaf-with-siblings-jti",
		MissionID:           "leaf-with-siblings-jti",
		Mission:             "branch aggregate",
		AllowedTools:        []string{"read"},
		MaxToolCalls:        10,
		MaxDurationSeconds:  300,
		DelegationAllowed:   false,
		MaxDelegationDepth:  0,
		ParentJTI:           "child-a",
		ParentTokenHash:     "child-a-hash",
		ReservedBudgetShare: 10,
		DelegationChain: []credential.DelegationChainLink{
			{
				JTI:                 "child-a",
				ParentJTI:           rootClaims.JWTID,
				MaxToolCalls:        20,
				ReservedBudgetShare: 20,
			},
			{
				JTI:                 "child-b",
				ParentJTI:           rootClaims.JWTID,
				MaxToolCalls:        20,
				ReservedBudgetShare: 15,
			},
			{
				JTI:          rootClaims.JWTID,
				MaxToolCalls: rootClaims.MaxToolCalls,
			},
		},
	}, key)
	if err != nil {
		t.Fatalf("SignPassportClaims() error: %v", err)
	}

	_, err = AuditChainBudget(rootToken, leafToken, key.PublicKey)
	if err == nil {
		t.Fatal("expected audit error for unsigned sibling contribution, got nil")
	}
	if !errors.Is(err, ErrAuditUnverifiedBranch) {
		t.Fatalf("AuditChainBudget() error = %v, want ErrAuditUnverifiedBranch", err)
	}
}

func TestAuditChainBudgetRejectsUnsignedIntermediateContribution(t *testing.T) {
	key := governanceSigningKey(t)
	rootToken := governanceRootToken(t, key, 30)
	rootClaims, err := credential.VerifyPassport(rootToken, key.PublicKey)
	if err != nil {
		t.Fatalf("VerifyPassport(root) error: %v", err)
	}

	now := time.Now()
	leafToken, err := credential.SignPassportClaims(credential.PassportClaims{
		Issuer:              rootClaims.Issuer,
		Subject:             "leaf-via-unsigned-mid",
		Audience:            rootClaims.Audience,
		IssuedAt:            now.Unix(),
		NotBefore:           now.Unix(),
		ExpiresAt:           now.Add(5 * time.Minute).Unix(),
		JWTID:               "leaf-via-unsigned-mid-jti",
		MissionID:           "leaf-via-unsigned-mid-jti",
		Mission:             "unsigned intermediate attack",
		AllowedTools:        []string{"read"},
		MaxToolCalls:        5,
		MaxDurationSeconds:  300,
		DelegationAllowed:   false,
		MaxDelegationDepth:  0,
		ParentJTI:           "unsigned-mid",
		ParentTokenHash:     "unsigned-mid-hash",
		ReservedBudgetShare: 5,
		DelegationChain: []credential.DelegationChainLink{
			{
				JTI:                 "unsigned-mid",
				ParentJTI:           rootClaims.JWTID,
				MaxToolCalls:        5,
				ReservedBudgetShare: 50,
			},
			{
				JTI:          rootClaims.JWTID,
				MaxToolCalls: rootClaims.MaxToolCalls + 100,
			},
		},
	}, key)
	if err != nil {
		t.Fatalf("SignPassportClaims() error: %v", err)
	}

	_, err = AuditChainBudget(rootToken, leafToken, key.PublicKey)
	if err == nil {
		t.Fatal("expected audit error for unsigned contributing branch, got nil")
	}
	if !errors.Is(err, ErrAuditUnverifiedBranch) {
		t.Fatalf("AuditChainBudget() error = %v, want ErrAuditUnverifiedBranch", err)
	}

	var auditErr *AuditError
	if !errors.As(err, &auditErr) {
		t.Fatalf("AuditChainBudget() error = %T, want *AuditError", err)
	}
	if auditErr.BranchJTI != "unsigned-mid" {
		t.Fatalf("AuditError.BranchJTI = %q, want %q", auditErr.BranchJTI, "unsigned-mid")
	}
}

func governanceSigningKey(t *testing.T) *credential.SigningKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	return &credential.SigningKey{
		PrivateKey: priv,
		PublicKey:  pub,
		KeyID:      "governance-test-key",
	}
}

func governanceRootToken(t *testing.T, key *credential.SigningKey, ceiling int) string {
	t.Helper()
	token, err := credential.IssuePassport(credential.MissionPassport{
		AgentID:            "root",
		Mission:            "coordinate fan-out",
		AllowedTools:       []string{"read", "write"},
		MaxToolCalls:       ceiling,
		MaxDurationSeconds: 600,
		DelegationAllowed:  true,
		MaxDelegationDepth: 3,
	}, key, &credential.IssuePassportOptions{
		TTL: 600 * time.Second,
	})
	if err != nil {
		t.Fatalf("IssuePassport() error: %v", err)
	}
	return token
}

func hashTokenForTest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
