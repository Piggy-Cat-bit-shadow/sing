package badoption

import (
	"regexp"

	"github.com/sagernet/sing/common/json"
)

// Regexp is a regular expression option.
//
// The option does not own a compiled expression. Every option decoded from the
// same expression points at one canonical [regexp.Regexp], so a configuration
// with many include/exclude fields for the same pattern pays for one parse and
// one compiled program, not one per field.
//
// The canonical object is never exposed: [Regexp.Build] returns an independent
// shallow copy. The copy shares the immutable compiled program but has its own
// Longest flag, which is the only part of a [regexp.Regexp] that matching
// mutates. Callers are therefore free to call [regexp.Regexp.Longest] on a
// Build result without changing the meaning of any other holder.
type Regexp struct {
	compiled *regexp.Regexp
}

// NewRegexp returns an option for expression. The compiled form is shared with
// every other option for the same expression, exactly as if the option had been
// decoded from JSON, and the returned error is the one regexp.Compile would
// report for it.
func NewRegexp(expression string) (*Regexp, error) {
	compiled, err := sharedRegexp(expression)
	if err != nil {
		return nil, err
	}
	return &Regexp{compiled: compiled}, nil
}

// Build returns an independent compiled expression.
//
// The returned [regexp.Regexp] shares the immutable compiled program with every
// other option for the same expression, but it is a distinct object: calling
// [regexp.Regexp.Longest] on it does not affect another Build result or any
// other configuration holding the same expression. Callers must not rely on
// two Build calls returning the same pointer.
//
// A nil receiver, and an option that was never decoded, build to nil.
func (r *Regexp) Build() *regexp.Regexp {
	if r == nil || r.compiled == nil {
		return nil
	}
	// This is what (*regexp.Regexp).Copy does. A compiled Regexp is immutable
	// except for the longest flag, so a shallow copy is enough to isolate
	// Longest; Copy itself is deprecated for the lock-contention use it was
	// introduced for, which does not apply here.
	compiled := *r.compiled
	return &compiled
}

func (r *Regexp) MarshalJSON() ([]byte, error) {
	var expression string
	if r != nil && r.compiled != nil {
		expression = r.compiled.String()
	}
	return json.Marshal(expression)
}

func (r *Regexp) UnmarshalJSON(content []byte) error {
	var stringValue string
	err := json.Unmarshal(content, &stringValue)
	if err != nil {
		return err
	}
	compiled, err := sharedRegexp(stringValue)
	if err != nil {
		return err
	}
	r.compiled = compiled
	return nil
}
