// Package spfer evaluates SPF (RFC 7208) records for a client IP address.
//
// Besides the RFC-strict result, it reports which directive matched (the full
// include chain down to the leaf mechanism) and every error encountered.
// CheckAll and CheckHostAll also report every other directive chain that
// matches the IP.
// Unlike a strict implementation, evaluation continues past the RFC processing
// limits (10 DNS-mechanism lookups, 2 void lookups, 10 MX names), so the caller
// also learns what the result would have been without them (EffectiveResult).
// A hard per-subtree lookup budget and explicit loop detection keep broken
// records from looping forever.
package spfer

import (
	"strings"
)

// Result is the outcome of an SPF evaluation (RFC 7208 §2.6).
type Result int

const (
	None Result = iota
	Neutral
	Pass
	Fail
	SoftFail
	TempError
	PermError
)

func (r Result) String() string {
	switch r {
	case None:
		return "none"
	case Neutral:
		return "neutral"
	case Pass:
		return "pass"
	case Fail:
		return "fail"
	case SoftFail:
		return "softfail"
	case TempError:
		return "temperror"
	case PermError:
		return "permerror"
	}
	return "unknown"
}

// Qualifier is the prefix of a mechanism. Modifiers (redirect) have no
// qualifier and use QualNone.
type Qualifier byte

const (
	QualNone     Qualifier = 0
	QualPass     Qualifier = '+'
	QualFail     Qualifier = '-'
	QualSoftFail Qualifier = '~'
	QualNeutral  Qualifier = '?'
)

func (q Qualifier) String() string {
	if q == QualNone {
		return ""
	}
	return string(q)
}

func (q Qualifier) result() Result {
	switch q {
	case QualFail:
		return Fail
	case QualSoftFail:
		return SoftFail
	case QualNeutral:
		return Neutral
	}
	return Pass
}

// Kind identifies a mechanism, or the redirect modifier in a match chain.
type Kind int

const (
	KindAll Kind = iota
	KindInclude
	KindA
	KindMX
	KindPTR
	KindIP4
	KindIP6
	KindExists
	KindRedirect
)

func (k Kind) String() string {
	switch k {
	case KindAll:
		return "all"
	case KindInclude:
		return "include"
	case KindA:
		return "a"
	case KindMX:
		return "mx"
	case KindPTR:
		return "ptr"
	case KindIP4:
		return "ip4"
	case KindIP6:
		return "ip6"
	case KindExists:
		return "exists"
	case KindRedirect:
		return "redirect"
	}
	return "unknown"
}

// CheckResult is returned by Check and CheckHost.
type CheckResult struct {
	// Result is the RFC 7208 strict result. It is PermError whenever a soft
	// limit was breached, even if EffectiveResult is something else.
	Result Result
	// EffectiveResult is the result as if the soft limits did not exist.
	EffectiveResult Result
	// Match is the directive chain that produced EffectiveResult, or nil when
	// no mechanism matched (default neutral, none, or an error).
	Match *Match
	// Matches holds every directive chain whose leaf mechanism matches the IP,
	// in record order. The all mechanism is not reported. Only CheckAll and
	// CheckHostAll set it.
	Matches []*Match
	// Errors holds every issue encountered, in order of occurrence.
	Errors []*Error
	// Lookups is the number of RFC-counted DNS-mechanism lookups (include, a,
	// mx, ptr, exists, redirect). It can exceed the limit of 10.
	Lookups int
	// VoidLookups is the number of lookups that returned NXDOMAIN or no data.
	VoidLookups int
	// Explanation is the expanded exp= string. It is only set when
	// EffectiveResult is Fail and WithExplanation was given.
	Explanation string
}

// Match is the chain of directives that matched. Chain[0] is the term of the
// queried domain's own record; the last element is the leaf mechanism.
type Match struct {
	Chain []Step
}

// Leaf returns the mechanism that actually matched the IP.
func (m *Match) Leaf() Step { return m.Chain[len(m.Chain)-1] }

// Top returns the directive of the queried domain's own record that matched.
func (m *Match) Top() Step { return m.Chain[0] }

func (m *Match) String() string {
	parts := make([]string, len(m.Chain))
	for i, s := range m.Chain {
		parts[i] = s.Term
	}
	return strings.Join(parts, " -> ")
}

// Step is one directive in a match or error chain.
type Step struct {
	Domain    string    // domain whose record contains this term
	Term      string    // raw term text, e.g. "include:_spf.google.com"
	Index     int       // position of the term in that record (0-based, version excluded)
	Qualifier Qualifier // QualNone for redirect
	Kind      Kind
}
