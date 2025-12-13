package torchwood

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

// Policy encodes the requirements for a set of (co)signatures on a
// c2sp.org/tlog-checkpoint.
//
// The Verifier method allows the policy to be passed in as the known parameter
// to [note.Open], while the Check method must be applied to [note.Note.Sigs]
// and [Checkpoint.Origin] after [note.Open] and [ParseCheckpoint].
type Policy interface {
	// Check returns nil if the provided signatures satisfy the policy.
	//
	// The signatures must already have been verified with their respective
	// verifiers, and would usually be obtained from [note.Note.Sigs].
	Check(origin string, sigs []note.Signature) error

	// Verifier implements [note.Verifiers], returning the Verifier for any of
	// the cosigners in the policy.
	Verifier(name string, hash uint32) (note.Verifier, error)
}

// SingleVerifierPolicy returns a Policy that requires a single verifier to have
// signed the note. The origin is not restricted.
func SingleVerifierPolicy(v note.Verifier) Policy {
	return &singleVerifierPolicy{v: v}
}

type singleVerifierPolicy struct {
	v note.Verifier
}

func (w *singleVerifierPolicy) Check(_ string, sigs []note.Signature) error {
	for _, sig := range sigs {
		if sig.Name == w.v.Name() && sig.Hash == w.v.KeyHash() {
			return nil
		}
	}
	return fmt.Errorf("verifier %q (%08x) did not sign", w.v.Name(), w.v.KeyHash())
}

func (w *singleVerifierPolicy) Verifier(name string, hash uint32) (note.Verifier, error) {
	if name == w.v.Name() && hash == w.v.KeyHash() {
		return w.v, nil
	}
	return nil, &note.UnknownVerifierError{Name: name, KeyHash: hash}
}

// ThresholdPolicy returns a Policy that requires at least n of the
// provided policies to be satisfied.
//
// It panics if n is less than zero or greater than the number of polcies.
func ThresholdPolicy(n int, policies ...Policy) Policy {
	if n < 0 || n > len(policies) {
		panic(fmt.Errorf("threshold of %d outside bounds for policies %s", n, policies))
	}
	return &thresholdPolicy{policies: policies, threshold: n}
}

type thresholdPolicy struct {
	policies  []Policy
	threshold int
}

func (w *thresholdPolicy) Check(origin string, sigs []note.Signature) error {
	satisfied := 0
	for _, p := range w.policies {
		if err := p.Check(origin, sigs); err == nil {
			satisfied++
		}
	}
	if satisfied >= w.threshold {
		return nil
	}
	return fmt.Errorf("only %d/%d policy components satisfied", satisfied, w.threshold)
}

func (w *thresholdPolicy) Verifier(name string, hash uint32) (note.Verifier, error) {
	var verifier note.Verifier
	for _, p := range w.policies {
		v, err := p.Verifier(name, hash)
		if _, ok := err.(*note.UnknownVerifierError); ok {
			continue
		}
		if err != nil {
			return nil, err
		}
		if verifier != nil {
			// This, for now, requires not having the same verifier in multiple
			// groups, which matches the Sigsum policy specification. If we
			// change our mind, we will need some way to check the verifiers for
			// equality.
			return nil, fmt.Errorf("multiple verifiers found for %q (%08x)", name, hash)
		}
		verifier = v
	}
	if verifier != nil {
		return verifier, nil
	}
	return nil, &note.UnknownVerifierError{Name: name, KeyHash: hash}
}

type originPolicy struct {
	origin string
}

// OriginPolicy returns a Policy that enforces the provided origin string.
//
// This is usually combined with a [SingleVerifierPolicy] for the log's public
// key Verifier, using [ThresholdPolicy] with a threshold of 2-of-2.
func OriginPolicy(origin string) Policy {
	return &originPolicy{origin: origin}
}

func (w *originPolicy) Check(origin string, sigs []note.Signature) error {
	if origin != w.origin {
		return fmt.Errorf("checkpoint origin mismatch: got %q, want %q", origin, w.origin)
	}
	return nil
}

func (w *originPolicy) Verifier(name string, hash uint32) (note.Verifier, error) {
	return nil, &note.UnknownVerifierError{Name: name, KeyHash: hash}
}

// ParsePolicy parses a [Policy] from the provided byte slice.
//
// The policy format is EXPERIMENTAL and may change in future releases. It is
// based on [the Sigsum policy format] but it uses vkeys instead of raw public
// keys. It is compatible with Tessera witness policies. It currently requires
// the checkpoint origin to match the log vkey name.
//
// [the Sigsum policy format]: https://git.glasklar.is/sigsum/core/sigsum-go/-/blob/main/doc/policy.md
func ParsePolicy(p []byte) (Policy, error) {
	var quorum string
	var logs []Policy
	policies := make(map[string]Policy)
	for i, line := range strings.Split(string(p), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if strings.Trim(line, " \t") == "" {
			continue
		}
		switch fields := strings.Fields(line); fields[0] {
		case "log":
			if len(fields) < 2 {
				return nil, fmt.Errorf("line %d: invalid log definition: %q", i+1, line)
			}
			v, err := note.NewVerifier(fields[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid log vkey %q: %w", i+1, fields[1], err)
			}
			logs = append(logs, ThresholdPolicy(2, OriginPolicy(v.Name()), SingleVerifierPolicy(v)))
		case "witness":
			if len(fields) < 3 {
				return nil, fmt.Errorf("line %d: invalid witness definition: %q", i+1, line)
			}
			name, vkey := fields[1], fields[2]
			if _, ok := policies[name]; ok {
				return nil, fmt.Errorf("line %d: duplicate component name: %q", i+1, name)
			}
			v, err := NewCosignatureVerifier(vkey)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid witness vkey %q: %w", i+1, vkey, err)
			}
			policies[name] = SingleVerifierPolicy(v)
		case "group":
			if len(fields) < 4 {
				return nil, fmt.Errorf("line %d: invalid group definition: %q", i+1, line)
			}
			name, nStr, children := fields[1], fields[2], fields[3:]
			if _, ok := policies[name]; ok {
				return nil, fmt.Errorf("line %d: duplicate component name: %q", i+1, name)
			}
			var n int
			switch nStr {
			case "any":
				n = 1
			case "all":
				n = len(children)
			default:
				var err error
				n, err = strconv.Atoi(nStr)
				if err != nil || n < 1 || n > len(children) {
					return nil, fmt.Errorf("line %d: invalid group threshold %q", i+1, nStr)
				}
			}
			c := make([]Policy, 0, len(children))
			for _, cn := range children {
				child, ok := policies[cn]
				if !ok {
					return nil, fmt.Errorf("line %d: unknown component %q in group %q definition", i+1, cn, name)
				}
				c = append(c, child)
			}
			policies[name] = ThresholdPolicy(n, c...)
		case "quorum":
			if len(fields) < 2 {
				return nil, fmt.Errorf("line %d: invalid quorum definition: %q", i+1, line)
			}
			if quorum != "" {
				return nil, fmt.Errorf("line %d: multiple quorum definitions", i+1)
			}
			quorum = fields[1]
		default:
			return nil, fmt.Errorf("line %d: unknown keyword: %q", i+1, fields[0])
		}
	}
	logPolicy := ThresholdPolicy(len(logs), logs...)
	switch quorum {
	case "":
		return nil, errors.New("no quorum defined in policy")
	case "none":
		return logPolicy, nil
	default:
		q, ok := policies[quorum]
		if !ok {
			return nil, fmt.Errorf("quorum %q not defined in policy", quorum)
		}
		return ThresholdPolicy(2, q, logPolicy), nil
	}
}
