package log

// A Rule classifies why a record was refused.
type Rule uint8

const (
	// RuleMalformed: not a valid record of its kind, whatever the chain.
	RuleMalformed Rule = iota + 1

	// RuleParent: it does not chain to what it was offered against — its
	// parent is not the head, or does not descend from this node's anchor.
	// Its ancestors may yet arrive.
	RuleParent

	// RuleUnauthorized: its signatures do not authorize it.
	RuleUnauthorized

	// RuleState: what it does breaks a rule of the state it applies to.
	RuleState
)

func (r Rule) String() string {
	switch r {
	case RuleMalformed:
		return "malformed"
	case RuleParent:
		return "parent"
	case RuleUnauthorized:
		return "unauthorized"
	case RuleState:
		return "state"
	}
	return "rule?"
}

// A RejectError is a record refused on its merits: offered again against the
// same chain, it is refused again. What else the package returns — storage
// errors, [RollbackError], [SchemaTooNewError], an [Alarm] — is about this
// node rather than the record.
type RejectError struct {
	Rule Rule
	err  error
}

func (e *RejectError) Error() string { return e.err.Error() }
func (e *RejectError) Unwrap() error { return e.err }

func reject(r Rule, err error) error { return &RejectError{Rule: r, err: err} }
