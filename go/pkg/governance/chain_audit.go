package governance

import (
	"crypto"
	"errors"
	"fmt"
	"sort"

	"github.com/gnanirahulnutakki/ardur/go/pkg/credential"
)

var ErrAuditUnverifiedBranch = errors.New("chain audit encountered unverified contributing branch")

// AuditBranch summarizes the discovered reservation total for one parent node.
type AuditBranch struct {
	ParentJTI          string
	ParentMaxToolCalls int
	DiscoveredReserved int
	Verified           bool
	Violation          bool
}

// AuditResult is the chain-only escrow-rights audit verdict.
type AuditResult struct {
	RootJTI                string
	LeafJTI                string
	RootMaxToolCalls       int
	DiscoveredReservedRoot int
	Violation              bool
	Branches               []AuditBranch
}

type auditNode struct {
	JTI                 string
	ParentJTI           string
	MaxToolCalls        int
	ReservedBudgetShare int
	Verified            bool
}

type AuditError struct {
	Err       error
	BranchJTI string
}

func (e *AuditError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.BranchJTI == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %s", e.Err.Error(), e.BranchJTI)
}

func (e *AuditError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func setAuditNode(nodesByJTI map[string]auditNode, node auditNode) {
	existing, ok := nodesByJTI[node.JTI]
	if ok && existing.Verified && !node.Verified {
		return
	}
	nodesByJTI[node.JTI] = node
}

// AuditChainBudget verifies the supplied root and leaf tokens, walks the leaf's
// signed delegation-chain snapshot back to the root, and sums
// reserved_budget_share for each discovered parent JTI without relying on any
// external session state.
func AuditChainBudget(rootToken, leafToken string, publicKey crypto.PublicKey) (*AuditResult, error) {
	rootClaims, err := credential.VerifyPassport(rootToken, publicKey)
	if err != nil {
		return nil, fmt.Errorf("verifying root token: %w", err)
	}
	leafClaims, err := credential.VerifyPassport(leafToken, publicKey)
	if err != nil {
		return nil, fmt.Errorf("verifying leaf token: %w", err)
	}

	// Re-validate the chain snapshot inside the audit path even though
	// VerifyPassport already does so. The audit must never infer "root-like"
	// status from ParentJTI before surfacing any delegation-chain error.
	chainEntries, err := credential.DelegationChainEntries(leafClaims)
	if err != nil {
		return nil, fmt.Errorf("validating leaf delegation chain: %w", err)
	}

	nodesByJTI := make(map[string]auditNode, len(chainEntries)+2)
	setAuditNode(nodesByJTI, auditNode{
		JTI:          rootClaims.JWTID,
		ParentJTI:    rootClaims.ParentJTI,
		MaxToolCalls: rootClaims.MaxToolCalls,
		Verified:     true,
	})
	setAuditNode(nodesByJTI, auditNode{
		JTI:                 leafClaims.JWTID,
		ParentJTI:           leafClaims.ParentJTI,
		MaxToolCalls:        leafClaims.MaxToolCalls,
		ReservedBudgetShare: leafClaims.ReservedBudgetShare,
		Verified:            true,
	})
	for _, entry := range chainEntries {
		setAuditNode(nodesByJTI, auditNode{
			JTI:                 entry.JTI,
			ParentJTI:           entry.ParentJTI,
			MaxToolCalls:        entry.MaxToolCalls,
			ReservedBudgetShare: entry.ReservedBudgetShare,
			Verified:            false,
		})
	}

	if err := ensureRootReachable(rootClaims.JWTID, leafClaims.JWTID, nodesByJTI); err != nil {
		return nil, err
	}

	reservedByParent := make(map[string]int)
	for _, n := range nodesByJTI {
		if n.ParentJTI == "" || n.ReservedBudgetShare <= 0 {
			continue
		}
		if !n.Verified {
			return nil, &AuditError{
				Err:       ErrAuditUnverifiedBranch,
				BranchJTI: n.JTI,
			}
		}
		reservedByParent[n.ParentJTI] += n.ReservedBudgetShare
	}

	branchJTIs := make([]string, 0, len(nodesByJTI))
	for jti := range nodesByJTI {
		branchJTIs = append(branchJTIs, jti)
	}
	sort.Strings(branchJTIs)

	branches := make([]AuditBranch, 0, len(branchJTIs))
	for _, jti := range branchJTIs {
		n := nodesByJTI[jti]
		if n.MaxToolCalls <= 0 {
			continue
		}
		discovered := reservedByParent[jti]
		branches = append(branches, AuditBranch{
			ParentJTI:          jti,
			ParentMaxToolCalls: n.MaxToolCalls,
			DiscoveredReserved: discovered,
			Verified:           n.Verified,
			Violation:          discovered > n.MaxToolCalls,
		})
	}

	rootReserved := reservedByParent[rootClaims.JWTID]
	return &AuditResult{
		RootJTI:                rootClaims.JWTID,
		LeafJTI:                leafClaims.JWTID,
		RootMaxToolCalls:       rootClaims.MaxToolCalls,
		DiscoveredReservedRoot: rootReserved,
		Violation:              rootReserved > rootClaims.MaxToolCalls,
		Branches:               branches,
	}, nil
}

func ensureRootReachable(rootJTI, leafJTI string, nodesByJTI map[string]auditNode) error {
	current := leafJTI
	seen := map[string]struct{}{}
	for current != "" {
		if current == rootJTI {
			return nil
		}
		if _, ok := seen[current]; ok {
			return fmt.Errorf("delegation chain contains a loop at %s", current)
		}
		seen[current] = struct{}{}

		n, ok := nodesByJTI[current]
		if !ok {
			return fmt.Errorf("delegation chain missing node for %s", current)
		}
		if n.ParentJTI == "" {
			break
		}
		current = n.ParentJTI
	}
	return fmt.Errorf("leaf chain does not reach supplied root %s", rootJTI)
}
