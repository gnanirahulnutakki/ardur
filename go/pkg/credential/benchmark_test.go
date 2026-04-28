package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func benchKeyPair(b *testing.B) (ed25519.PublicKey, ed25519.PrivateKey) {
	b.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	return pub, priv
}

func benchSigningKey(b *testing.B) *SigningKey {
	b.Helper()
	pub, priv := benchKeyPair(b)
	return &SigningKey{PrivateKey: priv, PublicKey: pub, KeyID: "bench-key"}
}

func benchBuilder(b *testing.B) *Builder {
	b.Helper()
	return NewBuilder(
		"https://vibap.example.com",
		"spiffe://ardur.dev/ns/default/sa/agent/instance/bench-001",
	).
		WithIdentity(
			"spiffe://ardur.dev/ns/default/sa/agent/instance/bench-001",
			"spiffe://ardur.dev/ns/default/sa/deployer",
			"",
		).
		WithIntent("sha256:abc123", "cedar", "sha256:policy789", []string{"read:db"}).
		WithTrust(0.3, 0.9, 85.0, "", "")
}

// BenchmarkCredentialBuild measures Build() performance (no signing).
func BenchmarkCredentialBuild(b *testing.B) {
	key := benchSigningKey(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := benchBuilder(b).Build(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCredentialBuildAllLayers measures Build() with all 5 layers.
func BenchmarkCredentialBuildAllLayers(b *testing.B) {
	key := benchSigningKey(b)

	b.ResetTimer()
	for b.Loop() {
		_, err := benchBuilder(b).
			WithProvenance("sha256:digest", "https://rekor.example.com/123", "sha256:model", "github-actions://...", "https://sbom.example.com").
			WithBaseline("sha256:profile", []string{"10.0.0.0/8:443"}, []string{"read", "write"}, nil, nil, 2).
			Build(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCredentialEncode measures Encode() (sign + serialize).
func BenchmarkCredentialEncode(b *testing.B) {
	key := benchSigningKey(b)
	cred, _ := benchBuilder(b).Build(key)

	b.ResetTimer()
	for b.Loop() {
		_, err := Encode(cred, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCredentialEncodeWithSD measures Encode() with selective disclosures.
func BenchmarkCredentialEncodeWithSD(b *testing.B) {
	key := benchSigningKey(b)
	cred, _ := benchBuilder(b).
		WithProvenance("sha256:digest", "", "", "", "").
		WithBaseline("sha256:profile", nil, nil, nil, nil, 0).
		WithSelectiveDisclosure("provenance", "baseline").
		Build(key)

	b.ResetTimer()
	for b.Loop() {
		_, err := Encode(cred, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCredentialDecode measures Decode() (parse without verify).
func BenchmarkCredentialDecode(b *testing.B) {
	key := benchSigningKey(b)
	cred, _ := benchBuilder(b).Build(key)
	encoded, _ := Encode(cred, key)

	b.ResetTimer()
	for b.Loop() {
		_, err := Decode(encoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCredentialVerify measures full Verify() (signature + claims).
func BenchmarkCredentialVerify(b *testing.B) {
	key := benchSigningKey(b)
	cred, _ := benchBuilder(b).Build(key)
	encoded, _ := Encode(cred, key)

	opts := &VerifyOptions{SkipStatusCheck: true}

	b.ResetTimer()
	for b.Loop() {
		result, err := Verify(encoded, key.PublicKey, opts)
		if err != nil {
			b.Fatal(err)
		}
		if !result.Valid {
			b.Fatalf("verification failed: %v", result.Errors)
		}
	}
}

// BenchmarkCredentialRoundtrip measures the full create→encode→verify cycle.
func BenchmarkCredentialRoundtrip(b *testing.B) {
	key := benchSigningKey(b)
	opts := &VerifyOptions{SkipStatusCheck: true}

	b.ResetTimer()
	for b.Loop() {
		cred, err := benchBuilder(b).Build(key)
		if err != nil {
			b.Fatal(err)
		}
		encoded, err := Encode(cred, key)
		if err != nil {
			b.Fatal(err)
		}
		result, err := Verify(encoded, key.PublicKey, opts)
		if err != nil {
			b.Fatal(err)
		}
		if !result.Valid {
			b.Fatalf("invalid: %v", result.Errors)
		}
	}
}

// BenchmarkStatusExtract measures status extraction from a large list.
func BenchmarkStatusExtract(b *testing.B) {
	statuses := make([]StatusValue, 10000)
	for i := range statuses {
		statuses[i] = StatusValue(i % 3)
	}
	compressed, _ := CompressStatusList(statuses, 2)
	bits, _ := decompressStatusList(compressed)

	b.ResetTimer()
	for b.Loop() {
		_, err := extractStatus(bits, 5000, 2)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkStatusCompressDecompress measures status list compression cycle.
func BenchmarkStatusCompressDecompress(b *testing.B) {
	statuses := make([]StatusValue, 10000)
	for i := range statuses {
		statuses[i] = StatusValue(i % 3)
	}

	b.ResetTimer()
	for b.Loop() {
		compressed, err := CompressStatusList(statuses, 2)
		if err != nil {
			b.Fatal(err)
		}
		_, err = decompressStatusList(compressed)
		if err != nil {
			b.Fatal(err)
		}
	}
}
