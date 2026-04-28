package aat

import (
	"crypto/ed25519"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// IssueRootOpts captures the AS-side inputs for AAT §3.7.3 root issuance.
type IssueRootOpts struct {
	JWTID              string
	Issuer             string
	Now                time.Time
	ExpiresAt          time.Time
	TokenType          AATType
	MaxDelegationDepth int
	HolderJWK          jose.JSONWebKey
	Authorization      []AuthorizationDetail
	Signer             ed25519.PrivateKey
	KeyID              string
}

// DeriveOpts captures the local holder inputs for AAT §6 derivation.
type DeriveOpts struct {
	JWTID              string
	Now                time.Time
	ExpiresAt          time.Time
	TokenType          AATType
	MaxDelegationDepth int
	HolderJWK          jose.JSONWebKey
	Authorization      []AuthorizationDetail
	Signer             ed25519.PrivateKey
	KeyID              string
}

// IssueRoot constructs the root AAT issued by the authorization server.
func IssueRoot(opts IssueRootOpts) (*Token, error) {
	// TODO(B.5/AAT §3.7.3 step 1): set iss to the AS URI.
	// TODO(B.5/AAT §3.7.3 step 2): mint a fresh jti (UUIDv7 recommended).
	// TODO(B.5/AAT §3.7.3 step 3): set iat/exp subject to AAT §4.4.
	// TODO(B.5/AAT §3.7.3 step 4): set aat_type to delegation or execution.
	// TODO(B.5/AAT §3.7.3 step 5): set del_depth=0, del_max_depth, par_hash absent.
	// TODO(B.5/AAT §3.7.3 step 6): bind holder cnf.jwk and validate it is public.
	// TODO(B.5/AAT §3.7.3 step 7): copy granted authorization_details.
	// TODO(B.5/AAT §3.7.3 step 8): validate URI-format tool identifiers against
	// requester identity where applicable.
	// TODO(B.5/AAT §3.7.3 step 9): sign with the AS Ed25519 key using go-jose.
	return nil, ErrIssueRootNotImplemented
}

// DeriveChild constructs a locally derived child token from a parent AAT.
func DeriveChild(parent *Token, opts DeriveOpts) (*Token, error) {
	// TODO(B.5/AAT §6 step 1): mint a fresh child jti.
	// TODO(B.5/AAT §6 step 2): set child iat/exp such that exp <= parent.exp and
	// all AAT §4.4 lifetime constraints hold [I3].
	// TODO(B.5/AAT §6 step 3): select child aat_type and enforce type-transition
	// key separation when parent/child token types differ [I2 + §3.1].
	// TODO(B.5/AAT §6 step 4): select a child tool set that is a subset of the
	// parent authorization set [I4].
	// TODO(B.5/AAT §6 step 5): narrow each tool's argument constraints per AAT
	// §4.5 subsumption rules [I4].
	// TODO(B.5/AAT §6 step 6): set child.del_depth = parent.del_depth + 1 [I2].
	// TODO(B.5/AAT §6 step 7): choose child.del_max_depth within the inclusive
	// bounds required by AAT §6 and §4.3 [I2].
	// TODO(B.5/AAT §6 step 8): compute child.par_hash over the parent's JWS
	// Signing Input [I5].
	// TODO(B.5/AAT §6 step 9): set child.cnf.jwk to the intended holder public key.
	// TODO(B.5/AAT §6 step 10): sign the child with the parent's holder key and
	// set iss to the JWK Thumbprint URI of the signing key [I1].
	// Tracking for I1-I5: docs/session-2026-04-14/06-briefs-issued/B5-go-aat-skeleton.md
	return nil, ErrDeriveChildNotImplemented
}
