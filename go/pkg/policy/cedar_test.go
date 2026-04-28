package policy

import (
	"context"
	"errors"
	"testing"
)

const testPermitPolicy = `permit(
  principal == VIBAP::Agent::"weather-bot",
  action == Action::"read_weather",
  resource == VIBAP::Resource::"weather-api"
);`

const testForbidPolicy = `forbid(
  principal,
  action == Action::"delete_data",
  resource
);`

const testConditionalPolicy = `permit(
  principal is VIBAP::Agent,
  action == Action::"read_weather",
  resource == VIBAP::Resource::"weather-api"
) when {
  principal.trust_tier == "full"
};`

const testMultiPolicy = `permit(
  principal == VIBAP::Agent::"weather-bot",
  action == Action::"read_weather",
  resource == VIBAP::Resource::"weather-api"
);

forbid(
  principal,
  action == Action::"delete_data",
  resource
);`

func TestCedarEngine_Compile(t *testing.T) {
	engine := NewCedarEngine()
	defer engine.Close()

	t.Run("valid policy", func(t *testing.T) {
		compiled, err := engine.Compile(context.Background(), testPermitPolicy)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if compiled.Hash == "" {
			t.Error("hash is empty")
		}
		if compiled.PolicyCount != 1 {
			t.Errorf("policy count = %d, want 1", compiled.PolicyCount)
		}
		if len(compiled.PolicyIDs) != 1 {
			t.Errorf("policy IDs count = %d, want 1", len(compiled.PolicyIDs))
		}
	})

	t.Run("multiple policies", func(t *testing.T) {
		compiled, err := engine.Compile(context.Background(), testMultiPolicy)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if compiled.PolicyCount != 2 {
			t.Errorf("policy count = %d, want 2", compiled.PolicyCount)
		}
	})

	t.Run("empty policy text", func(t *testing.T) {
		_, err := engine.Compile(context.Background(), "")
		if err == nil {
			t.Error("expected error for empty policy")
		}
		if !errors.Is(err, ErrPolicyParse) {
			t.Errorf("err = %v, want ErrPolicyParse", err)
		}
	})

	t.Run("invalid policy syntax", func(t *testing.T) {
		_, err := engine.Compile(context.Background(), "this is not valid cedar")
		if err == nil {
			t.Error("expected error for invalid policy")
		}
		if !errors.Is(err, ErrPolicyParse) {
			t.Errorf("err = %v, want ErrPolicyParse", err)
		}
	})

	t.Run("deterministic hash", func(t *testing.T) {
		c1, _ := engine.Compile(context.Background(), testPermitPolicy)
		c2, _ := engine.Compile(context.Background(), testPermitPolicy)
		if c1.Hash != c2.Hash {
			t.Errorf("hashes differ for identical policies: %s vs %s", c1.Hash, c2.Hash)
		}
	})

	t.Run("different policies different hash", func(t *testing.T) {
		c1, _ := engine.Compile(context.Background(), testPermitPolicy)
		c2, _ := engine.Compile(context.Background(), testForbidPolicy)
		if c1.Hash == c2.Hash {
			t.Error("different policies should have different hashes")
		}
	})
}

func TestCedarEngine_Evaluate(t *testing.T) {
	engine := NewCedarEngine()
	defer engine.Close()

	t.Run("permit matching request", func(t *testing.T) {
		compiled, err := engine.Compile(context.Background(), testPermitPolicy)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}

		entities := []Entity{
			{UID: EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"}},
			{UID: EntityRef{Type: "Action", ID: "read_weather"}},
			{UID: EntityRef{Type: "VIBAP::Resource", ID: "weather-api"}},
		}

		result, err := engine.Evaluate(context.Background(), compiled, entities, AuthzRequest{
			Principal: EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"},
			Action:    EntityRef{Type: "Action", ID: "read_weather"},
			Resource:  EntityRef{Type: "VIBAP::Resource", ID: "weather-api"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != DecisionAllow {
			t.Errorf("decision = %s, want allow (reasons=%v, errors=%v)", result.Decision, result.Reasons, result.Errors)
		}
		if result.EvalTime <= 0 {
			t.Error("eval time should be positive")
		}
	})

	t.Run("deny non-matching principal", func(t *testing.T) {
		compiled, _ := engine.Compile(context.Background(), testPermitPolicy)

		entities := []Entity{
			{UID: EntityRef{Type: "VIBAP::Agent", ID: "rogue-bot"}},
			{UID: EntityRef{Type: "Action", ID: "read_weather"}},
			{UID: EntityRef{Type: "VIBAP::Resource", ID: "weather-api"}},
		}

		result, err := engine.Evaluate(context.Background(), compiled, entities, AuthzRequest{
			Principal: EntityRef{Type: "VIBAP::Agent", ID: "rogue-bot"},
			Action:    EntityRef{Type: "Action", ID: "read_weather"},
			Resource:  EntityRef{Type: "VIBAP::Resource", ID: "weather-api"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Errorf("decision = %s, want deny", result.Decision)
		}
	})

	t.Run("forbid overrides permit", func(t *testing.T) {
		compiled, _ := engine.Compile(context.Background(), testMultiPolicy)

		entities := []Entity{
			{UID: EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"}},
			{UID: EntityRef{Type: "Action", ID: "delete_data"}},
			{UID: EntityRef{Type: "VIBAP::Resource", ID: "weather-api"}},
		}

		result, err := engine.Evaluate(context.Background(), compiled, entities, AuthzRequest{
			Principal: EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"},
			Action:    EntityRef{Type: "Action", ID: "delete_data"},
			Resource:  EntityRef{Type: "VIBAP::Resource", ID: "weather-api"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != DecisionDeny {
			t.Errorf("decision = %s, want deny (forbid should override)", result.Decision)
		}
	})

	t.Run("conditional policy with attributes", func(t *testing.T) {
		compiled, _ := engine.Compile(context.Background(), testConditionalPolicy)

		entitiesAllow := []Entity{
			{
				UID:        EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"},
				Attributes: map[string]any{"trust_tier": "full"},
			},
			{UID: EntityRef{Type: "Action", ID: "read_weather"}},
			{UID: EntityRef{Type: "VIBAP::Resource", ID: "weather-api"}},
		}

		result, err := engine.Evaluate(context.Background(), compiled, entitiesAllow, AuthzRequest{
			Principal: EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"},
			Action:    EntityRef{Type: "Action", ID: "read_weather"},
			Resource:  EntityRef{Type: "VIBAP::Resource", ID: "weather-api"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result.Decision != DecisionAllow {
			t.Errorf("decision = %s, want allow for trust_tier=full", result.Decision)
		}

		entitiesDeny := []Entity{
			{
				UID:        EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"},
				Attributes: map[string]any{"trust_tier": "quarantine"},
			},
			{UID: EntityRef{Type: "Action", ID: "read_weather"}},
			{UID: EntityRef{Type: "VIBAP::Resource", ID: "weather-api"}},
		}

		result2, err := engine.Evaluate(context.Background(), compiled, entitiesDeny, AuthzRequest{
			Principal: EntityRef{Type: "VIBAP::Agent", ID: "weather-bot"},
			Action:    EntityRef{Type: "Action", ID: "read_weather"},
			Resource:  EntityRef{Type: "VIBAP::Resource", ID: "weather-api"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if result2.Decision != DecisionDeny {
			t.Errorf("decision = %s, want deny for trust_tier=quarantine", result2.Decision)
		}
	})

	t.Run("nil compiled policy", func(t *testing.T) {
		_, err := engine.Evaluate(context.Background(), nil, nil, AuthzRequest{})
		if err == nil {
			t.Error("expected error for nil compiled policy")
		}
		if !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest", err)
		}
	})
}

func TestCedarEngine_SetEntities(t *testing.T) {
	engine := NewCedarEngine()
	defer engine.Close()

	entities := []Entity{
		{
			UID: EntityRef{Type: "VIBAP::Agent", ID: "bot-1"},
			Parents: []EntityRef{
				{Type: "VIBAP::Owner", ID: "deployer-1"},
			},
			Attributes: map[string]any{
				"trust_tier": "full",
				"score":      int64(85),
			},
		},
	}

	if err := engine.SetEntities(entities); err != nil {
		t.Fatalf("SetEntities: %v", err)
	}
}

func TestCedarEngine_Close(t *testing.T) {
	engine := NewCedarEngine()
	engine.Close()

	_, err := engine.Compile(context.Background(), testPermitPolicy)
	if !errors.Is(err, ErrEngineClosed) {
		t.Errorf("Compile after close: %v, want ErrEngineClosed", err)
	}

	_, err = engine.Evaluate(context.Background(), &CompiledPolicy{}, nil, AuthzRequest{})
	if !errors.Is(err, ErrEngineClosed) {
		t.Errorf("Evaluate after close: %v, want ErrEngineClosed", err)
	}

	if err := engine.SetEntities(nil); !errors.Is(err, ErrEngineClosed) {
		t.Errorf("SetEntities after close: %v, want ErrEngineClosed", err)
	}
}

func TestCedarEngine_EngineName(t *testing.T) {
	engine := NewCedarEngine()
	defer engine.Close()

	if engine.EngineName() != "cedar" {
		t.Errorf("EngineName() = %q, want cedar", engine.EngineName())
	}
}

// TestToCedarValueViaEntityAttributes exercises toCedarValue through Evaluate.
// Entity attributes and request context use buildCedarRecord -> toCedarValue.
func TestToCedarValueViaEntityAttributes(t *testing.T) {
	policy := `permit(
  principal is VIBAP::Agent,
  action == Action::"read",
  resource == VIBAP::Resource::"api"
) when { principal.flag == true };`

	engine := NewCedarEngine()
	defer engine.Close()

	compiled, err := engine.Compile(context.Background(), policy)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Entity attributes: string, int, int64, bool, []string, []any, map[string]any, float64 (default branch)
	entities := []Entity{
		{
			UID: EntityRef{Type: "VIBAP::Agent", ID: "bot"},
			Attributes: map[string]any{
				"flag":   true,
				"str":    "hello",
				"int":    42,
				"i64":    int64(99),
				"strs":   []string{"a", "b"},
				"anys":   []any{1, "x", true},
				"nested": map[string]any{"k": "v"},
				"float":  3.14, // exercises default branch in toCedarValue
			},
		},
		{UID: EntityRef{Type: "Action", ID: "read"}},
		{UID: EntityRef{Type: "VIBAP::Resource", ID: "api"}},
	}

	result, err := engine.Evaluate(context.Background(), compiled, entities, AuthzRequest{
		Principal: EntityRef{Type: "VIBAP::Agent", ID: "bot"},
		Action:    EntityRef{Type: "Action", ID: "read"},
		Resource:  EntityRef{Type: "VIBAP::Resource", ID: "api"},
		Context:   map[string]any{"ts": 12345, "ip": "1.2.3.4"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Decision != DecisionAllow {
		t.Errorf("decision = %s (reasons=%v, errors=%v)", result.Decision, result.Reasons, result.Errors)
	}
}

func TestCedarEngine_CloseIdempotent(t *testing.T) {
	engine := NewCedarEngine()

	if err := engine.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := engine.Close(); err != nil {
		t.Errorf("second Close: %v, want nil (idempotent)", err)
	}
}
