package log

import (
	"fmt"
	"strings"

	"github.com/nning/juist/types"
)

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

// An Alarm is a condition an operator has to resolve. While one is raised,
// [Authority.TrustedState] refuses to hand out membership state: a node that
// cannot tell who is a member must not guess.
type Alarm struct {
	// Forks are the conflicting branches.
	Forks []Orphan
}

func (a *Alarm) Error() string {
	var b strings.Builder
	b.WriteString("log: fork alarm: ")
	for i, f := range a.Forks {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "branch at %v (%d records): %s", f.Root, len(f.Records), f.Conflict)
	}
	b.WriteString(" — admin action required")
	return b.String()
}

// A RollbackError reports a checkpoint [Bootstrap] refused for an epoch below
// the one this node has adopted. Nothing is stored.
type RollbackError struct {
	// Floor is the highest epoch this node has adopted.
	Floor uint64

	// Offered is the epoch the rejected chain resolves to.
	Offered uint64

	// Records are the rejected records, so a caller can preserve them as
	// evidence even though they were not stored.
	Records []types.AUM
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf(
		"log: refusing records that would move the chain from epoch %d back to epoch %d; "+
			"this requires admin signatures, so treat it as a fork or a compromised quorum",
		e.Floor, e.Offered)
}

// A RollbackAlarm reports that fork choice over the records held picks a chain
// below the epoch floor: a branch this node applied first lost to a concurrent
// one, or a quorum rewrote history. The records are held and the floor stays;
// [Authority.TrustedState] refuses until a record on the chain, a change redone
// or a group secret rotated, brings it back to the floor.
type RollbackAlarm struct {
	// Floor is the highest epoch this node has adopted, Epoch the chain's.
	Floor, Epoch uint64

	// Branch is the root of a lost branch that reached the floor, or zero
	// where none is held, as after records were lost.
	Branch types.Hash
}

func (e *RollbackAlarm) Error() string {
	lost := ""
	if !e.Branch.IsZero() {
		lost = fmt.Sprintf(" for the branch at %v", e.Branch)
	}
	return fmt.Sprintf("log: rollback alarm: the chain went back from epoch %d to %d%s, "+
		"which this device does not follow — an admin redoes the lost changes or runs juist rotate group-secret",
		e.Floor, e.Epoch, lost)
}

// A SchemaTooNewError reports that a quorum has moved the network to a record
// schema this build does not implement. It is not a refusal of the record —
// the record is authorized and the network really has moved — but a statement
// that this node stops here. Nothing after it can be interpreted: a later
// record may carry a kind or a field this build has never heard of, and acting
// on the part it understands is the split view the closed record set exists to
// prevent.
//
// Unlike a fork alarm this does not withdraw membership state. The state the
// node holds was correct up to the upgrade, and tearing every tunnel down the
// moment an admin raises the schema would turn a planned change into an
// outage. What bounds how long that state may be acted on is the freshness
// TTL, which is M4's.
type SchemaTooNewError struct {
	// Version is the schema the network moved to, Implemented the newest this
	// build can act on, and At the record that made the change.
	Version     types.SchemaVersion
	Implemented types.SchemaVersion
	At          types.Hash
}

func (e *SchemaTooNewError) Error() string {
	return fmt.Sprintf(
		"log: the network moved to %v in record %v and this build implements %v; "+
			"this device holds the state up to that record and can apply nothing after it — "+
			"install a newer juist",
		e.Version, e.At, e.Implemented)
}

// A DisabledError reports that a [types.KindDisable] record has ended the
// network. It is final: no record undoes it.
type DisabledError struct {
	// At is the disable record.
	At types.Hash
}

func (e *DisabledError) Error() string {
	return fmt.Sprintf("log: the network was disabled with a break-glass secret in record %v", e.At)
}
