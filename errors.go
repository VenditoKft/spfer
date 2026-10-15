package spfer

import (
	"fmt"
	"strings"
)

// ErrorCode classifies an Error. Codes implement error, so they can be used as
// errors.Is targets: errors.Is(err, spfer.ErrLookupLimit).
type ErrorCode int

const (
	// ErrLookupLimit: more than 10 DNS-mechanism lookups (soft).
	ErrLookupLimit ErrorCode = iota + 1
	// ErrVoidLimit: more than 2 void lookups (soft).
	ErrVoidLimit
	// ErrMXLimit: an mx mechanism returned more than 10 names (soft).
	ErrMXLimit
	// ErrPTRLimit: a PTR lookup returned more than 10 names. Per RFC 7208 the
	// extra names are ignored; this is informational and does not change Result.
	ErrPTRLimit
	// ErrSubtreeBudget: a top-level subtree used up its hard lookup budget (soft).
	ErrSubtreeBudget
	// ErrLoop: an include/redirect points back to a domain on the current chain.
	ErrLoop
	// ErrSyntax: an SPF record failed to parse.
	ErrSyntax
	// ErrNoRecord: an include or redirect target has no SPF record.
	ErrNoRecord
	// ErrMultipleRecords: a domain publishes more than one SPF record.
	ErrMultipleRecords
	// ErrDNS: a DNS lookup failed temporarily (timeout, SERVFAIL, ...).
	ErrDNS
	// ErrMacro: a macro could not be expanded.
	ErrMacro
	// ErrInvalidDomain: a target domain is malformed after macro expansion.
	ErrInvalidDomain
)

func (c ErrorCode) Error() string {
	switch c {
	case ErrLookupLimit:
		return "dns lookup limit exceeded"
	case ErrVoidLimit:
		return "void lookup limit exceeded"
	case ErrMXLimit:
		return "mx name limit exceeded"
	case ErrPTRLimit:
		return "ptr name limit exceeded"
	case ErrSubtreeBudget:
		return "subtree lookup budget exhausted"
	case ErrLoop:
		return "include loop detected"
	case ErrSyntax:
		return "syntax error"
	case ErrNoRecord:
		return "no spf record"
	case ErrMultipleRecords:
		return "multiple spf records"
	case ErrDNS:
		return "dns error"
	case ErrMacro:
		return "macro error"
	case ErrInvalidDomain:
		return "invalid domain"
	}
	return "unknown error"
}

// Soft reports whether the code is a limit violation that turns Result into
// PermError while evaluation continues for EffectiveResult.
func (c ErrorCode) Soft() bool {
	switch c {
	case ErrLookupLimit, ErrVoidLimit, ErrMXLimit, ErrSubtreeBudget:
		return true
	}
	return false
}

// Error describes one issue found during evaluation.
type Error struct {
	Code  ErrorCode
	Chain []Step // directives leading to the place where it happened
	Msg   string
	Err   error // underlying cause, if any
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Code.Error())
	if e.Msg != "" {
		b.WriteString(": ")
		b.WriteString(e.Msg)
	}
	if len(e.Chain) > 0 {
		m := Match{Chain: e.Chain}
		fmt.Fprintf(&b, " (at %s)", m.String())
	}
	if e.Err != nil {
		b.WriteString(": ")
		b.WriteString(e.Err.Error())
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrLookupLimit) and friends work.
func (e *Error) Is(target error) bool {
	c, ok := target.(ErrorCode)
	return ok && c == e.Code
}
