package aat

import (
	"errors"
	"testing"
)

type fakeConstraintHandler struct {
	typ           ConstraintType
	checkErr      error
	subsumesOK    bool
	subsumesErr   error
	checkCalls    int
	subsumesCalls int
}

func (h *fakeConstraintHandler) Type() ConstraintType {
	return h.typ
}

func (h *fakeConstraintHandler) Check(value any, constraint *Constraint) error {
	h.checkCalls++
	return h.checkErr
}

func (h *fakeConstraintHandler) Subsumes(parent, child *Constraint) (bool, error) {
	h.subsumesCalls++
	return h.subsumesOK, h.subsumesErr
}

func TestTokenIsRoot(t *testing.T) {
	tests := []struct {
		name string
		tok  *Token
		want bool
	}{
		{name: "nil token", tok: nil, want: false},
		{name: "root token", tok: &Token{DelegationDepth: 0}, want: true},
		{name: "child depth", tok: &Token{DelegationDepth: 1}, want: false},
		{name: "parent hash present", tok: &Token{DelegationDepth: 0, ParentHash: "parent"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tok.IsRoot(); got != tt.want {
				t.Fatalf("IsRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegistryRegisterAndLookup(t *testing.T) {
	var nilRegistry *Registry
	if err := nilRegistry.Register(&fakeConstraintHandler{typ: ConstraintTypeExact}); !errors.Is(err, ErrNilConstraintHandler) {
		t.Fatalf("nil registry Register() error = %v, want ErrNilConstraintHandler", err)
	}

	registry := NewRegistry()
	if err := registry.Register(nil); !errors.Is(err, ErrNilConstraintHandler) {
		t.Fatalf("nil handler Register() error = %v, want ErrNilConstraintHandler", err)
	}

	handler := &fakeConstraintHandler{typ: ConstraintTypeExact}
	if err := registry.Register(handler); err != nil {
		t.Fatalf("Register() unexpected error: %v", err)
	}
	if err := registry.Register(&fakeConstraintHandler{typ: ConstraintTypeExact}); !errors.Is(err, ErrDuplicateConstraintType) {
		t.Fatalf("duplicate Register() error = %v, want ErrDuplicateConstraintType", err)
	}

	got, ok := registry.Lookup(ConstraintTypeExact)
	if !ok || got != handler {
		t.Fatalf("Lookup() = (%v, %v), want registered handler", got, ok)
	}
	if got, ok := registry.Lookup(ConstraintTypeRange); ok || got != nil {
		t.Fatalf("missing Lookup() = (%v, %v), want nil,false", got, ok)
	}

	var nilLookup *Registry
	if got, ok := nilLookup.Lookup(ConstraintTypeExact); ok || got != nil {
		t.Fatalf("nil Lookup() = (%v, %v), want nil,false", got, ok)
	}
}

func TestDefaultConstraintRegistryHasCoreHandlers(t *testing.T) {
	coreTypes := []ConstraintType{
		ConstraintTypeExact,
		ConstraintTypePattern,
		ConstraintTypeRange,
		ConstraintTypeOneOf,
		ConstraintTypeNotOneOf,
		ConstraintTypeContains,
		ConstraintTypeSubset,
		ConstraintTypeRegex,
		ConstraintTypeCEL,
		ConstraintTypeWildcard,
		ConstraintTypeAll,
		ConstraintTypeAny,
		ConstraintTypeNot,
	}

	for _, typ := range coreTypes {
		t.Run(string(typ), func(t *testing.T) {
			if _, ok := DefaultConstraintRegistry.Lookup(typ); !ok {
				t.Fatalf("DefaultConstraintRegistry missing handler for %q", typ)
			}
		})
	}
}

func TestCheckConstraintDispatchesAndFailsClosed(t *testing.T) {
	if err := CheckConstraint("value", nil); !errors.Is(err, ErrNilConstraint) {
		t.Fatalf("nil CheckConstraint() error = %v, want ErrNilConstraint", err)
	}
	if err := CheckConstraint("value", &Constraint{ConstraintType: ConstraintType("extension")}); !errors.Is(err, ErrUnknownConstraintType) {
		t.Fatalf("unknown CheckConstraint() error = %v, want ErrUnknownConstraintType", err)
	}
	if err := CheckConstraint("value", &Constraint{ConstraintType: ConstraintTypeExact, Value: "value"}); !errors.Is(err, ErrConstraintCheckNotImplemented) {
		t.Fatalf("core CheckConstraint() error = %v, want ErrConstraintCheckNotImplemented", err)
	}
}

func TestSubsumesConstraintDispatchesAndFailsClosed(t *testing.T) {
	parent := &Constraint{ConstraintType: ConstraintTypeWildcard}
	child := &Constraint{ConstraintType: ConstraintTypeExact, Value: "value"}

	for _, tt := range []struct {
		name   string
		parent *Constraint
		child  *Constraint
	}{
		{name: "nil parent", parent: nil, child: child},
		{name: "nil child", parent: parent, child: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := SubsumesConstraint(tt.parent, tt.child)
			if ok {
				t.Fatal("SubsumesConstraint() returned true for nil input")
			}
			if !errors.Is(err, ErrNilConstraint) {
				t.Fatalf("SubsumesConstraint() error = %v, want ErrNilConstraint", err)
			}
		})
	}

	ok, err := SubsumesConstraint(parent, &Constraint{ConstraintType: ConstraintType("extension")})
	if ok {
		t.Fatal("SubsumesConstraint() returned true for unknown child constraint")
	}
	if !errors.Is(err, ErrUnknownConstraintType) {
		t.Fatalf("unknown SubsumesConstraint() error = %v, want ErrUnknownConstraintType", err)
	}

	ok, err = SubsumesConstraint(parent, child)
	if ok {
		t.Fatal("SubsumesConstraint() returned true for unimplemented core rule")
	}
	if !errors.Is(err, ErrConstraintSubsumptionNotImplemented) {
		t.Fatalf("core SubsumesConstraint() error = %v, want ErrConstraintSubsumptionNotImplemented", err)
	}
}

func TestCoreConstraintHandlerDelegates(t *testing.T) {
	checkErr := errors.New("check called")
	subsumesErr := errors.New("subsumes called")
	checkCalled := false
	subsumesCalled := false

	handler := coreConstraintHandler{
		typ: ConstraintTypeExact,
		check: func(value any, constraint *Constraint) error {
			checkCalled = true
			if value != "value" {
				t.Fatalf("Check received value %v, want value", value)
			}
			return checkErr
		},
		subsumes: func(parent, child *Constraint) (bool, error) {
			subsumesCalled = true
			if parent == nil || child == nil {
				t.Fatal("Subsumes received nil constraints")
			}
			return true, subsumesErr
		},
	}

	if handler.Type() != ConstraintTypeExact {
		t.Fatalf("Type() = %q, want %q", handler.Type(), ConstraintTypeExact)
	}
	if err := handler.Check("value", &Constraint{ConstraintType: ConstraintTypeExact}); !errors.Is(err, checkErr) {
		t.Fatalf("Check() error = %v, want %v", err, checkErr)
	}
	ok, err := handler.Subsumes(&Constraint{ConstraintType: ConstraintTypeWildcard}, &Constraint{ConstraintType: ConstraintTypeExact})
	if !ok {
		t.Fatal("Subsumes() ok = false, want true")
	}
	if !errors.Is(err, subsumesErr) {
		t.Fatalf("Subsumes() error = %v, want %v", err, subsumesErr)
	}
	if !checkCalled || !subsumesCalled {
		t.Fatalf("callbacks called = (%v, %v), want both true", checkCalled, subsumesCalled)
	}
}

func TestIssueAndDeriveSkeletonsFailClosed(t *testing.T) {
	if tok, err := IssueRoot(IssueRootOpts{}); tok != nil || !errors.Is(err, ErrIssueRootNotImplemented) {
		t.Fatalf("IssueRoot() = (%v, %v), want nil ErrIssueRootNotImplemented", tok, err)
	}
	if tok, err := DeriveChild(&Token{JWTID: "parent"}, DeriveOpts{}); tok != nil || !errors.Is(err, ErrDeriveChildNotImplemented) {
		t.Fatalf("DeriveChild() = (%v, %v), want nil ErrDeriveChildNotImplemented", tok, err)
	}
}

func TestVerifyChainSkeletonReturnsDenyEnvelope(t *testing.T) {
	root := &Token{JWTID: "root", DelegationDepth: 0}
	child := &Token{JWTID: "child", DelegationDepth: 1, ParentHash: "parent"}
	result, err := VerifyChain([]*Token{root, child}, nil, "tool", map[string]interface{}{"arg": "value"}, "pop.jwt")
	if !errors.Is(err, ErrVerifyChainNotImplemented) {
		t.Fatalf("VerifyChain() error = %v, want ErrVerifyChainNotImplemented", err)
	}
	if result == nil {
		t.Fatal("VerifyChain() result is nil")
	}
	if result.Verdict != VerdictDeny {
		t.Fatalf("Verdict = %q, want %q", result.Verdict, VerdictDeny)
	}
	if result.Leaf != child {
		t.Fatalf("Leaf = %v, want child token", result.Leaf)
	}
	if len(result.Links) != 1 || result.Links[0].Index != 0 || result.Links[0].Parent != root || result.Links[0].Child != child {
		t.Fatalf("Links = %#v, want root->child link", result.Links)
	}
	if result.PoP == nil || result.PoP.Compact != "pop.jwt" {
		t.Fatalf("PoP = %#v, want compact pop jwt", result.PoP)
	}
	if result.FailedStep != "aat-section-7" {
		t.Fatalf("FailedStep = %q, want aat-section-7", result.FailedStep)
	}
	if !errors.Is(result.Cause, ErrVerifyChainNotImplemented) {
		t.Fatalf("Cause = %v, want ErrVerifyChainNotImplemented", result.Cause)
	}
	if len(result.Notes) == 0 {
		t.Fatal("Notes is empty")
	}
}
