package aat

import (
	"crypto/ed25519"
	"time"
)

// BuildPoPOpts captures the inputs needed to construct a PoP JWT per AAT §5.2.
type BuildPoPOpts struct {
	JWTID  string
	Now    time.Time
	Leaf   *Token
	Tool   string
	Args   map[string]interface{}
	Signer ed25519.PrivateKey
	KeyID  string
}

// VerifyPoPOpts captures verifier-local knobs for AAT §5.3 / §7 step 7.
type VerifyPoPOpts struct {
	Now       time.Time
	ClockSkew time.Duration
}

// BuildPoPJWT constructs the compact PoP JWT bound to the leaf token holder.
func BuildPoPJWT(opts BuildPoPOpts) (string, error) {
	// TODO(B.5/AAT §5.2): serialize the full PoP payload with RFC 8785 JCS
	// canonicalization before JWS signing; do not canonicalize hta in isolation.
	// TODO(B.5/AAT §5.2): sign only with the private key corresponding to
	// leaf.cnf.jwk and emit EdDSA/Ed25519 headers via go-jose.
	return "", ErrBuildPoPJWTNotImplemented
}

// VerifyPoPJWT verifies the PoP JWT against a fully validated execution token.
func VerifyPoPJWT(leaf *Token, tool string, args map[string]interface{}, popJWT string, opts VerifyPoPOpts) (*PoPJWT, error) {
	// TODO(B.5/AAT §5.3 / §7 step 7a): verify the PoP signature under
	// leaf.cnf.jwk [I6].
	// TODO(B.5/AAT §7 step 7b): require pop_jwt.aat_id == leaf.jti.
	// TODO(B.5/AAT §7 step 7c): require pop_jwt.aat_tool == tool.
	// TODO(B.5/AAT §7 step 7d): compare JCS-canonicalized HTA bytes to the
	// independently canonicalized invocation args.
	// TODO(B.5/AAT §7 step 7e): enforce the accepted iat clock-tolerance window.
	// Tracking for I6: docs/session-2026-04-14/06-briefs-issued/B5-go-aat-skeleton.md
	return nil, ErrVerifyPoPJWTNotImplemented
}

// VerifyPoP is a convenience alias retained for the B.5 brief wording.
func VerifyPoP(leaf *Token, tool string, args map[string]interface{}, popJWT string, opts VerifyPoPOpts) (*PoPJWT, error) {
	return VerifyPoPJWT(leaf, tool, args, popJWT, opts)
}

// CanonicalizeHTA returns the RFC 8785/JCS byte representation needed by AAT
// §5.2 and §7 step 7d.
func CanonicalizeHTA(hta map[string]interface{}) ([]byte, error) {
	// TODO(B.5/AAT §5.2): wire in a real RFC 8785 implementation for whole-
	// payload canonicalization and reuse it for hta equality checks.
	return nil, ErrCanonicalizationNotImplemented
}
