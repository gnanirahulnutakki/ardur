package credential

import (
	"testing"
)

func TestTierFromScore(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{"quarantine low", 0, TierQuarantine},
		{"quarantine mid", 39.9, TierQuarantine},
		{"limited boundary", 40, TierLimited},
		{"limited mid", 55, TierLimited},
		{"limited high", 69.9, TierLimited},
		{"full boundary", 70, TierFull},
		{"full mid", 85, TierFull},
		{"full max", 100, TierFull},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TierFromScore(tt.score)
			if got != tt.expected {
				t.Errorf("TierFromScore(%f) = %q, want %q", tt.score, got, tt.expected)
			}
		})
	}
}

func TestStatusValueString(t *testing.T) {
	tests := []struct {
		status   StatusValue
		expected string
	}{
		{StatusValid, "VALID"},
		{StatusInvalid, "INVALID"},
		{StatusSuspended, "SUSPENDED"},
		{StatusValue(0x03), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.expected {
				t.Errorf("StatusValue(%d).String() = %q, want %q", tt.status, got, tt.expected)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Verify critical constants match the spec
	if VIBAPTypeURI != "https://vibap.ardur.dev/credentials/AgentPassport/v1" {
		t.Errorf("VIBAPTypeURI = %q, expected VIBAP type URI", VIBAPTypeURI)
	}
	if MediaTypeDCSDJWT != "dc+sd-jwt" {
		t.Errorf("MediaTypeDCSDJWT = %q, expected dc+sd-jwt", MediaTypeDCSDJWT)
	}
	if MediaTypeKBJWT != "kb+jwt" {
		t.Errorf("MediaTypeKBJWT = %q, expected kb+jwt", MediaTypeKBJWT)
	}
	if SDAlgorithm != "sha-256" {
		t.Errorf("SDAlgorithm = %q, expected sha-256", SDAlgorithm)
	}
}
