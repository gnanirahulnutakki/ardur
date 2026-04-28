package aat

// VerifyChain is the offline enforcement algorithm defined in AAT §7.
//
// Input contract:
//   - chain is ordered root -> leaf
//   - trustAnchors holds root public keys (raw bytes for now; follow-up work
//     will normalize these into explicit JWK/Ed25519 verifier types)
//   - tool/args/popJWT are the invocation-time presentation inputs
func VerifyChain(chain []*Token, trustAnchors [][]byte, tool string, args map[string]interface{}, popJWT string) (*VerifyResult, error) {
	// F6 fix (April 15 2026 auggie audit): fail-CLOSED default verdict.
	// Skeleton functions MUST return VerdictDeny, not VerdictIndeterminate —
	// callers that inspect only the Verdict field (ignoring the error) would
	// otherwise treat "not implemented" as "might be OK" and proceed. This is
	// the skeleton's permanent safe state until the AAT §7 steps land.
	result := &VerifyResult{
		Verdict: VerdictDeny,
		Chain:   chain,
		Notes: []string{
			"skeleton only: see PLAN.md §B.5 and docs/session-2026-04-14/06-briefs-issued/B5-go-aat-skeleton.md",
			"fail-closed default verdict=deny per auggie F6 finding (2026-04-15)",
		},
	}
	if len(chain) > 0 {
		result.Leaf = chain[len(chain)-1]
	}
	for i := 1; i < len(chain); i++ {
		result.Links = append(result.Links, ChainLink{
			Index:  i - 1,
			Parent: chain[i-1],
			Child:  chain[i],
		})
	}
	if popJWT != "" {
		result.PoP = &PoPJWT{Compact: popJWT}
	}

	// TODO(B.5/AAT §7 step 1): reject empty chains [ErrDenyStep1EmptyChain].
	// TODO(B.5/AAT §7 step 2): enforce MAX_TOKEN_SIZE / MAX_STACK_SIZE and do
	// minimal jti extraction for cycle detection before full claim parsing
	// [ErrDenyStep2ATokenTooLarge, ErrDenyStep2BChainTooLarge,
	// ErrDenyStep2CInvalidPayload, ErrDenyStep2CMissingJTI,
	// ErrDenyStep2CDuplicateJTI].
	// TODO(B.5/AAT §7 step 3): verify the root token signature and required root
	// claims (3a-3n) [ErrDenyStep3AInvalidRootAlg ... ErrDenyStep3NRootAuthorization].
	// TODO(B.5/AAT §7 step 4): verify every parent/child link (4a-4s), including:
	//   - I1 signer linkage and issuer thumbprint binding [ErrInvariantI1NotImplemented]
	//   - I2 delegation depth monotonicity [ErrInvariantI2NotImplemented]
	//   - I3 ttl monotonicity [ErrInvariantI3NotImplemented]
	//   - I4 capability monotonicity [ErrInvariantI4NotImplemented]
	//   - I5 parent hash linkage [ErrInvariantI5NotImplemented]
	// Tracking doc: docs/session-2026-04-14/06-briefs-issued/B5-go-aat-skeleton.md
	// TODO(B.5/AAT §7 step 5): confirm len(chain) == leaf.del_depth + 1
	// [ErrDenyStep5ChainLengthMismatch].
	// TODO(B.5/AAT §7 step 6): validate the leaf execution token and invocation
	// args (6a-6c) [ErrDenyStep6ALeafAuthorization ... ErrDenyStep6CDelegationLeaf].
	// TODO(B.5/AAT §7 step 7): verify the PoP JWT and JCS-canonicalized hta
	// equality (7a-7e) [ErrInvariantI6NotImplemented, ErrDenyStep7APoPSignature
	// ... ErrDenyStep7EPopIAT].
	// TODO(B.5/AAT §7 step 8): return VerdictPermit only after all prior steps
	// succeed without denial.
	result.FailedStep = "aat-section-7"
	result.Cause = ErrVerifyChainNotImplemented
	return result, ErrVerifyChainNotImplemented
}
