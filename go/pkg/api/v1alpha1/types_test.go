package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSchemeRegistration(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme failed: %v", err)
	}

	gvk := schema.GroupVersionKind{Group: GroupName, Version: Version, Kind: "AgentPassport"}
	obj, err := scheme.New(gvk)
	if err != nil {
		t.Fatalf("scheme.New(AgentPassport) failed: %v", err)
	}
	if _, ok := obj.(*AgentPassport); !ok {
		t.Fatalf("expected *AgentPassport, got %T", obj)
	}

	gvk = schema.GroupVersionKind{Group: GroupName, Version: Version, Kind: "AgentPassportList"}
	obj, err = scheme.New(gvk)
	if err != nil {
		t.Fatalf("scheme.New(AgentPassportList) failed: %v", err)
	}
	if _, ok := obj.(*AgentPassportList); !ok {
		t.Fatalf("expected *AgentPassportList, got %T", obj)
	}
}

func TestSchemeGroupVersion(t *testing.T) {
	if SchemeGroupVersion.Group != GroupName {
		t.Errorf("expected group %q, got %q", GroupName, SchemeGroupVersion.Group)
	}
	if SchemeGroupVersion.Version != Version {
		t.Errorf("expected version %q, got %q", Version, SchemeGroupVersion.Version)
	}
}

func TestResource(t *testing.T) {
	gr := Resource("agentpassports")
	if gr.Group != GroupName {
		t.Errorf("expected group %q, got %q", GroupName, gr.Group)
	}
	if gr.Resource != "agentpassports" {
		t.Errorf("expected resource %q, got %q", "agentpassports", gr.Resource)
	}
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name      string
		got, want string
	}{
		{"GroupName", GroupName, "vibap.ardur.dev"},
		{"Version", Version, "v1alpha1"},
		{"AnnotationCredential", AnnotationCredential, "vibap.ardur.dev/credential"},
		{"AnnotationTrustTier", AnnotationTrustTier, "vibap.ardur.dev/trust-tier"},
		{"AnnotationCompliance", AnnotationCompliance, "vibap.ardur.dev/compliance-level"},
		{"LabelManagedBy", LabelManagedBy, "vibap.ardur.dev/managed-by"},
		{"LabelTrustTier", LabelTrustTier, "vibap.ardur.dev/trust-tier"},
		{"FinalizerName", FinalizerName, "vibap.ardur.dev/cleanup"},
		{"ConditionReady", ConditionReady, "Ready"},
		{"ConditionCredentialIssued", ConditionCredentialIssued, "CredentialIssued"},
		{"ReasonIssued", ReasonIssued, "Issued"},
		{"ReasonFailed", ReasonFailed, "Failed"},
		{"ReasonGovernanceInvalid", ReasonGovernanceInvalid, "GovernanceInvalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestAgentPassportDeepCopy(t *testing.T) {
	orig := &AgentPassport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-agent",
			Namespace: "default",
		},
		Spec: AgentPassportSpec{
			Identity: IdentitySpec{
				SPIFFEID: "spiffe://example.org/agent/test",
				OwnerID:  "spiffe://example.org/team/platform",
			},
			Intent: IntentSpec{
				InlinePolicy:     "permit(principal, action, resource);",
				PermittedActions: []string{"read", "write"},
				PolicyRef: &PolicyReference{
					Name: "my-policy",
					Key:  "policy.cedar",
				},
			},
			Trust: TrustSpec{
				StaticCapabilityScore: 0.8,
				HistoricalReputation:  0.9,
				Thresholds: &TrustThresholds{
					FullTier:    float64Ptr(70),
					LimitedTier: float64Ptr(40),
				},
			},
			Credential: CredentialSpec{
				TTL:                 &metav1.Duration{Duration: 3600000000000},
				SelectiveDisclosure: []string{"provenance"},
			},
			Provenance: &ProvenanceSpec{
				ImageRef:    "ghcr.io/test/agent:v1",
				RequireSLSA: true,
			},
			Baseline: &BaselineSpec{
				ProfileMode:        "enforce",
				MaxDelegationDepth: 3,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
			},
			Governance: &GovernanceSpec{
				Enabled: true,
				InlineDeclaration: &InlineDeclaration{
					AllowedActions:        []string{"read"},
					AllowedTools:          []string{"tool"},
					AllowedSideEffects:    []string{"none"},
					MaxSiblingDelegations: 1,
					Metadata:              map[string]string{"team": "platform"},
				},
			},
		},
		Status: AgentPassportStatus{
			ComplianceLevel: "verified",
			TrustTier:       "full",
			CompositeScore:  85.0,
			Conditions: []metav1.Condition{
				{Type: ConditionReady, Status: metav1.ConditionTrue, Reason: ReasonIssued, Message: "ok"},
			},
		},
	}

	copied := orig.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	if copied.Name != orig.Name {
		t.Errorf("Name mismatch: got %q, want %q", copied.Name, orig.Name)
	}

	// Mutate the copy and verify original is unaffected
	copied.Spec.Intent.PermittedActions[0] = "MUTATED"
	if orig.Spec.Intent.PermittedActions[0] == "MUTATED" {
		t.Error("DeepCopy did not deep-copy PermittedActions slice")
	}

	copied.Spec.Trust.Thresholds.FullTier = float64Ptr(99)
	if *orig.Spec.Trust.Thresholds.FullTier == 99 {
		t.Error("DeepCopy did not deep-copy TrustThresholds")
	}

	copied.Status.Conditions[0].Message = "MUTATED"
	if orig.Status.Conditions[0].Message == "MUTATED" {
		t.Error("DeepCopy did not deep-copy Conditions")
	}

	copied.Spec.Credential.SelectiveDisclosure[0] = "MUTATED"
	if orig.Spec.Credential.SelectiveDisclosure[0] == "MUTATED" {
		t.Error("DeepCopy did not deep-copy SelectiveDisclosure")
	}

	copied.Spec.Governance.InlineDeclaration.Metadata["team"] = "security"
	if orig.Spec.Governance.InlineDeclaration.Metadata["team"] == "security" {
		t.Error("DeepCopy did not deep-copy governance metadata")
	}
}

func TestGovernanceSpecValidate(t *testing.T) {
	valid := &GovernanceSpec{
		Enabled: true,
		Mode:    "monitor",
		InlineDeclaration: &InlineDeclaration{
			AllowedActions:        []string{"read"},
			AllowedTools:          []string{"reader"},
			AllowedSideEffects:    []string{"none"},
			MaxSiblingDelegations: 1,
		},
		EnforcementPolicy: &EnforcementPolicy{
			OnViolation:   "alert",
			MaxViolations: 1,
		},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("expected valid governance spec, got %v", err)
	}

	tests := []struct {
		name string
		spec *GovernanceSpec
	}{
		{
			name: "enabled without declaration",
			spec: &GovernanceSpec{Enabled: true},
		},
		{
			name: "both inline and ref",
			spec: &GovernanceSpec{
				Enabled: true,
				InlineDeclaration: &InlineDeclaration{
					AllowedActions: []string{"read"},
					AllowedTools:   []string{"reader"},
				},
				DeclarationRef: &DeclarationReference{Name: "decl"},
			},
		},
		{
			name: "invalid side effect",
			spec: &GovernanceSpec{
				Enabled: true,
				InlineDeclaration: &InlineDeclaration{
					AllowedActions:     []string{"read"},
					AllowedTools:       []string{"reader"},
					AllowedSideEffects: []string{"write_object"},
				},
			},
		},
		{
			name: "negative max sibling",
			spec: &GovernanceSpec{
				Enabled: true,
				InlineDeclaration: &InlineDeclaration{
					AllowedActions:        []string{"read"},
					AllowedTools:          []string{"reader"},
					MaxSiblingDelegations: -1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.spec.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAgentPassportDeepCopyObject(t *testing.T) {
	ap := &AgentPassport{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
	}

	obj := ap.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}
	if _, ok := obj.(*AgentPassport); !ok {
		t.Fatalf("expected *AgentPassport, got %T", obj)
	}
}

func TestAgentPassportListDeepCopy(t *testing.T) {
	orig := &AgentPassportList{
		Items: []AgentPassport{
			{ObjectMeta: metav1.ObjectMeta{Name: "ap1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "ap2"}},
		},
	}

	copied := orig.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}
	if len(copied.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(copied.Items))
	}

	copied.Items[0].Name = "MUTATED"
	if orig.Items[0].Name == "MUTATED" {
		t.Error("DeepCopy did not deep-copy Items")
	}
}

func TestNilDeepCopy(t *testing.T) {
	var ap *AgentPassport
	if ap.DeepCopy() != nil {
		t.Error("nil AgentPassport.DeepCopy should return nil")
	}

	var list *AgentPassportList
	if list.DeepCopy() != nil {
		t.Error("nil AgentPassportList.DeepCopy should return nil")
	}

	var spec *AgentPassportSpec
	if spec.DeepCopy() != nil {
		t.Error("nil AgentPassportSpec.DeepCopy should return nil")
	}

	var status *AgentPassportStatus
	if status.DeepCopy() != nil {
		t.Error("nil AgentPassportStatus.DeepCopy should return nil")
	}

	var intent *IntentSpec
	if intent.DeepCopy() != nil {
		t.Error("nil IntentSpec.DeepCopy should return nil")
	}

	var ts *TrustSpec
	if ts.DeepCopy() != nil {
		t.Error("nil TrustSpec.DeepCopy should return nil")
	}

	var thresholds *TrustThresholds
	if thresholds.DeepCopy() != nil {
		t.Error("nil TrustThresholds.DeepCopy should return nil")
	}

	var cred *CredentialSpec
	if cred.DeepCopy() != nil {
		t.Error("nil CredentialSpec.DeepCopy should return nil")
	}
}

func TestDeepCopyObjectNil(t *testing.T) {
	var ap *AgentPassport
	if ap.DeepCopyObject() != nil {
		t.Error("nil AgentPassport.DeepCopyObject should return nil")
	}

	var list *AgentPassportList
	if list.DeepCopyObject() != nil {
		t.Error("nil AgentPassportList.DeepCopyObject should return nil")
	}
}

func float64Ptr(f float64) *float64 {
	return &f
}
