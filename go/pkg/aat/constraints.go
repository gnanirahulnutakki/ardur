package aat

// ConstraintHandler defines the extension point required by AAT §3.5.
// Implementations MUST fail closed when they cannot resolve a handler for a
// constraint type encountered during I4 subsumption or leaf-time check
// evaluation.
type ConstraintHandler interface {
	Type() ConstraintType
	Check(value any, constraint *Constraint) error
	Subsumes(parent, child *Constraint) (bool, error)
}

// ConstraintRegistry is the minimal interface needed for core and extension
// constraint registration.
type ConstraintRegistry interface {
	Register(handler ConstraintHandler) error
	Lookup(constraintType ConstraintType) (ConstraintHandler, bool)
}

// Registry is the default in-memory registry implementation used by the AAT
// scaffold.
type Registry struct {
	handlers map[ConstraintType]ConstraintHandler
}

// NewRegistry constructs an empty registry.
func NewRegistry() *Registry {
	return &Registry{handlers: make(map[ConstraintType]ConstraintHandler)}
}

// Register installs a handler for one constraint type.
func (r *Registry) Register(handler ConstraintHandler) error {
	if r == nil {
		return ErrNilConstraintHandler
	}
	if handler == nil {
		return ErrNilConstraintHandler
	}
	if _, exists := r.handlers[handler.Type()]; exists {
		return ErrDuplicateConstraintType
	}
	r.handlers[handler.Type()] = handler
	return nil
}

// Lookup resolves a handler by wire constraint type.
func (r *Registry) Lookup(constraintType ConstraintType) (ConstraintHandler, bool) {
	if r == nil {
		return nil, false
	}
	handler, ok := r.handlers[constraintType]
	return handler, ok
}

type coreConstraintHandler struct {
	typ      ConstraintType
	check    func(value any, constraint *Constraint) error
	subsumes func(parent, child *Constraint) (bool, error)
}

func (h coreConstraintHandler) Type() ConstraintType { return h.typ }

func (h coreConstraintHandler) Check(value any, constraint *Constraint) error {
	return h.check(value, constraint)
}

func (h coreConstraintHandler) Subsumes(parent, child *Constraint) (bool, error) {
	return h.subsumes(parent, child)
}

// DefaultConstraintRegistry registers only the AAT §3.4 core types. Extension
// types are intentionally deferred.
var DefaultConstraintRegistry = newCoreConstraintRegistry()

func newCoreConstraintRegistry() *Registry {
	registry := NewRegistry()
	handlers := []ConstraintHandler{
		coreConstraintHandler{typ: ConstraintTypeExact, check: CheckExact, subsumes: SubsumesExact},
		coreConstraintHandler{typ: ConstraintTypePattern, check: CheckPattern, subsumes: SubsumesPattern},
		coreConstraintHandler{typ: ConstraintTypeRange, check: CheckRange, subsumes: SubsumesRange},
		coreConstraintHandler{typ: ConstraintTypeOneOf, check: CheckOneOf, subsumes: SubsumesOneOf},
		coreConstraintHandler{typ: ConstraintTypeNotOneOf, check: CheckNotOneOf, subsumes: SubsumesNotOneOf},
		coreConstraintHandler{typ: ConstraintTypeContains, check: CheckContains, subsumes: SubsumesContains},
		coreConstraintHandler{typ: ConstraintTypeSubset, check: CheckSubset, subsumes: SubsumesSubset},
		coreConstraintHandler{typ: ConstraintTypeRegex, check: CheckRegex, subsumes: SubsumesRegex},
		coreConstraintHandler{typ: ConstraintTypeCEL, check: CheckCEL, subsumes: SubsumesCEL},
		coreConstraintHandler{typ: ConstraintTypeWildcard, check: CheckWildcard, subsumes: SubsumesWildcard},
		coreConstraintHandler{typ: ConstraintTypeAll, check: CheckAll, subsumes: SubsumesAll},
		coreConstraintHandler{typ: ConstraintTypeAny, check: CheckAny, subsumes: SubsumesAny},
		coreConstraintHandler{typ: ConstraintTypeNot, check: CheckNot, subsumes: SubsumesNot},
	}
	for _, handler := range handlers {
		if err := registry.Register(handler); err != nil {
			panic(err)
		}
	}
	return registry
}

// CheckConstraint dispatches the leaf-time check predicate for the supplied
// constraint through the default registry.
func CheckConstraint(value any, constraint *Constraint) error {
	if constraint == nil {
		return ErrNilConstraint
	}
	handler, ok := DefaultConstraintRegistry.Lookup(constraint.ConstraintType)
	if !ok {
		return ErrUnknownConstraintType
	}
	return handler.Check(value, constraint)
}

// SubsumesConstraint dispatches the I4 check for a parent/child pair through
// the default registry. Dispatch is keyed by the child's type because cross-type
// attenuation rules are specified from the derived constraint's perspective in
// AAT §4.5.
func SubsumesConstraint(parent, child *Constraint) (bool, error) {
	if parent == nil || child == nil {
		return false, ErrNilConstraint
	}
	handler, ok := DefaultConstraintRegistry.Lookup(child.ConstraintType)
	if !ok {
		return false, ErrUnknownConstraintType
	}
	return handler.Subsumes(parent, child)
}

// CheckExact validates AAT §3.4 exact constraints.
func CheckExact(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 exact): implement exact equality check.
	return ErrConstraintCheckNotImplemented
}

// SubsumesExact validates the AAT §4.5 exact cross-type attenuation rules.
func SubsumesExact(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 exact): exact may subsume parent exact/pattern/range/
	// one_of/regex/wildcard under the normative rules.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckPattern validates AAT §3.4 pattern constraints.
func CheckPattern(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 pattern): implement glob evaluation with the draft's
	// restricted syntax (single-star, question mark, character classes).
	return ErrConstraintCheckNotImplemented
}

// SubsumesPattern validates the conservative syntactic containment rules in
// AAT §4.5 for pattern constraints.
func SubsumesPattern(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 pattern): support exact->pattern and terminal-wildcard
	// prefix narrowing without semantic glob containment.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckRange validates AAT §3.4 range constraints.
func CheckRange(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 range): implement numeric bounds and inclusivity.
	return ErrConstraintCheckNotImplemented
}

// SubsumesRange validates the AAT §4.5 range narrowing rules.
func SubsumesRange(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 range): enforce tighter/equal min/max bounds and
	// monotonic inclusivity changes.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckOneOf validates AAT §3.4 one_of constraints.
func CheckOneOf(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 one_of): implement membership check.
	return ErrConstraintCheckNotImplemented
}

// SubsumesOneOf validates AAT §4.5 one_of subset attenuation.
func SubsumesOneOf(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 one_of): child values must be a subset of parent values.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckNotOneOf validates AAT §3.4 not_one_of constraints.
func CheckNotOneOf(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 not_one_of): implement exclusion membership check.
	return ErrConstraintCheckNotImplemented
}

// SubsumesNotOneOf validates AAT §4.5 not_one_of superset attenuation.
func SubsumesNotOneOf(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 not_one_of): child excluded set must be a superset of
	// parent excluded set.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckContains validates AAT §3.4 contains constraints.
func CheckContains(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 contains): implement array superset check.
	return ErrConstraintCheckNotImplemented
}

// SubsumesContains validates AAT §4.5 contains attenuation.
func SubsumesContains(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 contains): child required set must be a superset of
	// parent required set.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckSubset validates AAT §3.4 subset constraints.
func CheckSubset(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 subset): implement array subset check.
	return ErrConstraintCheckNotImplemented
}

// SubsumesSubset validates AAT §4.5 subset attenuation.
func SubsumesSubset(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 subset): child allowed set must be a subset of the
	// parent allowed set.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckRegex validates AAT §3.4 regex constraints.
func CheckRegex(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 regex): document and implement the supported regex
	// dialect before enabling runtime use.
	return ErrConstraintCheckNotImplemented
}

// SubsumesRegex validates the conservative regex rules in AAT §4.5.
func SubsumesRegex(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 regex): allow regex->regex only on exact pattern-string
	// equality; exact children can target regex parents via runtime match.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckCEL validates AAT §3.4 cel constraints.
func CheckCEL(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 cel): integrate a CEL runtime that guarantees boolean
	// results and deterministic evaluation.
	return ErrConstraintCheckNotImplemented
}

// SubsumesCEL validates the balanced-parentheses conjunction rule in AAT §4.5.
func SubsumesCEL(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 cel): implement verbatim parent-expression embedding and
	// balanced-parentheses validation without semantic containment.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckWildcard validates AAT §3.4 wildcard constraints.
func CheckWildcard(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 wildcard): wildcard accepts any value by definition.
	return ErrConstraintCheckNotImplemented
}

// SubsumesWildcard validates AAT §4.5 wildcard attenuation.
func SubsumesWildcard(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 wildcard): wildcard is valid only when both parent and
	// child are wildcard; any other child type may target a wildcard parent via
	// its own cross-type rules.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckAll validates AAT §3.4 all constraints.
func CheckAll(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 all): evaluate all child clauses recursively.
	return ErrConstraintCheckNotImplemented
}

// SubsumesAll validates the one-to-one clause matching rules in AAT §4.5.
func SubsumesAll(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 all): implement subsumption-keyed matching with distinct
	// child-clause assignment and backtracking where needed.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckAny validates AAT §3.4 any constraints.
func CheckAny(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 any): evaluate child clauses with OR semantics.
	return ErrConstraintCheckNotImplemented
}

// SubsumesAny validates the AAT §4.5 any attenuation rules.
func SubsumesAny(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 any): every derived clause must be subsumed by at least
	// one parent clause; empty derived any is invalid.
	return false, ErrConstraintSubsumptionNotImplemented
}

// CheckNot validates AAT §3.4 not constraints.
func CheckNot(value any, constraint *Constraint) error {
	// TODO(B.5/AAT §3.4 not): evaluate the nested predicate and negate it.
	return ErrConstraintCheckNotImplemented
}

// SubsumesNot validates the conservative JCS-identity rule in AAT §4.5.
func SubsumesNot(parent, child *Constraint) (bool, error) {
	// TODO(B.5/AAT §4.5 not): permit only structurally identical not->not
	// constraints after JCS canonicalization.
	return false, ErrConstraintSubsumptionNotImplemented
}
