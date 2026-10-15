package spfer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// evaluator holds the state of one Check/CheckHost call.
type evaluator struct {
	ctx context.Context
	o   *options
	r   *cachingResolver
	ip  netip.Addr
	env macroEnv // base macro values; domain is filled in per record

	lookups, voids int
	lookupLimitHit bool
	voidLimitHit   bool
	soft           bool // a soft limit was breached: strict result is permerror
	errs           []*Error

	active []string // domains on the current include/redirect chain

	validatedNames []string // for %{p}, computed lazily
	validatedDone  bool

	exp *expSource // exp= of the record that produced the final result
}

type expSource struct {
	spec   string
	domain string
}

// budget is the hard lookup budget shared by one top-level subtree.
type budget struct {
	left      int
	exhausted bool
}

func (e *evaluator) newBudget() *budget { return &budget{left: e.o.subtreeBudget} }

// record appends an error to the result's error list and returns it.
func (e *evaluator) record(code ErrorCode, chain []Step, cause error, format string, args ...any) *Error {
	err := &Error{Code: code, Chain: cloneChain(chain), Msg: fmt.Sprintf(format, args...), Err: cause}
	e.errs = append(e.errs, err)
	if code.Soft() {
		e.soft = true
	}
	return err
}

func cloneChain(c []Step) []Step { return append([]Step(nil), c...) }

func appendStep(chain []Step, s Step) []Step {
	return append(cloneChain(chain), s)
}

// checkHost evaluates the SPF record of domain. chain is the path of
// directives leading here. On a match it returns the full chain down to the
// leaf mechanism. A non-nil *Error means evaluation ended in permerror or
// temperror (given by the returned Result).
//
// top is true only for the queried domain's own record: its include and
// redirect terms each get a fresh budget, everything else uses b.
// expEligible marks records whose exp= applies to the final result (the top
// record and redirect targets, but not includes).
func (e *evaluator) checkHost(domain string, chain []Step, b *budget, top, expEligible bool) (Result, []Step, *Error) {
	domain = normalizeDomain(domain)
	e.active = append(e.active, domain)
	defer func() { e.active = e.active[:len(e.active)-1] }()

	rec, res, err := e.fetchRecord(domain, chain, !top)
	if rec == nil {
		return res, nil, err
	}

	for _, m := range rec.Mechanisms {
		step := Step{Domain: domain, Term: m.Raw, Index: m.Index, Qualifier: m.Qualifier, Kind: m.Kind}
		here := appendStep(chain, step)
		matched, sub, err := e.evalMechanism(m, domain, here, b, top)
		if err != nil {
			return errResult(err), nil, err
		}
		if matched {
			if expEligible {
				e.setExp(rec, domain)
			}
			if sub != nil {
				return m.Qualifier.result(), sub, nil
			}
			return m.Qualifier.result(), here, nil
		}
	}

	if rec.Redirect != nil {
		mod := rec.Redirect
		step := Step{Domain: domain, Term: mod.Raw, Index: mod.Index, Kind: KindRedirect}
		here := appendStep(chain, step)
		rb := b
		if top {
			rb = e.newBudget()
		}
		if err := e.countLookup(here, rb); err != nil {
			return e.budgetOut(err, top)
		}
		target, err := e.targetDomain(mod.Value, domain, here)
		if err != nil {
			return PermError, nil, err
		}
		if err := e.checkLoop(target, here); err != nil {
			return PermError, nil, err
		}
		res, sub, err := e.checkHost(target, here, rb, false, expEligible)
		if err != nil {
			if top && errors.Is(err, ErrSubtreeBudget) {
				return Neutral, nil, nil
			}
			return res, nil, err
		}
		if res == None {
			err := e.record(ErrNoRecord, here, nil, "redirect target %s has no SPF record", target)
			return PermError, nil, err
		}
		return res, sub, nil
	}

	if expEligible {
		e.exp = nil
	}
	return Neutral, nil, nil
}

// budgetOut handles running out of budget on a top-level redirect: the
// effective result treats it as not evaluated (default neutral).
func (e *evaluator) budgetOut(err *Error, top bool) (Result, []Step, *Error) {
	if top {
		return Neutral, nil, nil
	}
	return PermError, nil, err
}

func errResult(err *Error) Result {
	if err.Code == ErrDNS {
		return TempError
	}
	return PermError
}

func (e *evaluator) setExp(rec *Record, domain string) {
	if rec.Exp == nil {
		e.exp = nil
		return
	}
	e.exp = &expSource{spec: rec.Exp.Value, domain: domain}
}

// fetchRecord looks up and parses the SPF record of domain. When rec is nil,
// res/err is the outcome. nested selects include/redirect semantics, where a
// missing record is reported by the caller.
func (e *evaluator) fetchRecord(domain string, chain []Step, nested bool) (*Record, Result, *Error) {
	if !validDomain(domain) {
		if nested {
			return nil, PermError, e.record(ErrInvalidDomain, chain, nil, "%q", domain)
		}
		return nil, None, nil
	}
	txts, err := e.r.LookupTXT(e.ctx, domain)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if nested {
				e.countVoid(chain)
			}
			return nil, None, nil
		}
		return nil, TempError, e.record(ErrDNS, chain, err, "TXT %s", domain)
	}
	var spf []string
	for _, t := range txts {
		if isSPFRecord(t) {
			spf = append(spf, t)
		}
	}
	switch len(spf) {
	case 0:
		return nil, None, nil
	case 1:
	default:
		return nil, PermError, e.record(ErrMultipleRecords, chain, nil, "%s publishes %d SPF records", domain, len(spf))
	}
	rec, perr := Parse(spf[0])
	if perr != nil {
		pe := perr.(*Error)
		pe.Chain = cloneChain(chain)
		pe.Msg = domain + ": " + pe.Msg
		e.errs = append(e.errs, pe)
		return nil, PermError, pe
	}
	return rec, None, nil
}

// evalMechanism evaluates one mechanism. sub is the match chain returned by an
// include (nil for leaf mechanisms).
func (e *evaluator) evalMechanism(m Mechanism, domain string, here []Step, b *budget, top bool) (bool, []Step, *Error) {
	switch m.Kind {
	case KindAll:
		return true, nil, nil
	case KindIP4, KindIP6:
		return m.Prefix.Contains(e.ip), nil, nil
	case KindInclude:
		return e.evalInclude(m, domain, here, b, top)
	}

	if b.exhausted {
		return false, nil, nil
	}
	if err := e.countLookup(here, b); err != nil {
		if top {
			// Root budget: skip the remaining top-level DNS mechanisms.
			return false, nil, nil
		}
		return false, nil, err
	}
	target := domain
	if m.Domain != "" {
		var err *Error
		if target, err = e.targetDomain(m.Domain, domain, here); err != nil {
			return false, nil, err
		}
	}
	switch m.Kind {
	case KindA:
		return e.evalA(m, target, here)
	case KindMX:
		return e.evalMX(m, target, here, b, top)
	case KindPTR:
		return e.evalPTR(target, here, b, top)
	case KindExists:
		return e.evalExists(target, here)
	}
	return false, nil, nil
}

func (e *evaluator) evalInclude(m Mechanism, domain string, here []Step, b *budget, top bool) (bool, []Step, *Error) {
	ib := b
	if top {
		ib = e.newBudget()
	}
	if err := e.countLookup(here, ib); err != nil {
		if top {
			return false, nil, nil
		}
		return false, nil, err
	}
	target, err := e.targetDomain(m.Domain, domain, here)
	if err != nil {
		return false, nil, err
	}
	if err := e.checkLoop(target, here); err != nil {
		return false, nil, err
	}
	res, sub, err := e.checkHost(target, here, ib, false, false)
	if err != nil {
		if top && errors.Is(err, ErrSubtreeBudget) {
			// The include's own subtree ran out; move on to the next term.
			return false, nil, nil
		}
		return false, nil, err
	}
	switch res {
	case Pass:
		return true, sub, nil
	case None:
		return false, nil, e.record(ErrNoRecord, here, nil, "include target %s has no SPF record", target)
	}
	return false, nil, nil
}

func (e *evaluator) evalA(m Mechanism, target string, here []Step) (bool, []Step, *Error) {
	ips, err := e.lookupIP(target, here, true)
	if err != nil {
		return false, nil, err
	}
	return e.matchAny(ips, m), nil, nil
}

func (e *evaluator) evalMX(m Mechanism, target string, here []Step, b *budget, top bool) (bool, []Step, *Error) {
	hosts, err := e.r.LookupMX(e.ctx, target)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			e.countVoid(here)
			return false, nil, nil
		}
		return false, nil, e.record(ErrDNS, here, err, "MX %s", target)
	}
	hosts = dropNullMX(hosts)
	if len(hosts) > defaultMXLimit {
		e.record(ErrMXLimit, here, nil, "%s has %d MX names", target, len(hosts))
	}
	for _, h := range hosts {
		if err := e.charge(here, b); err != nil {
			if top {
				return false, nil, nil
			}
			return false, nil, err
		}
		ips, err := e.lookupIP(h, here, false)
		if err != nil {
			return false, nil, err
		}
		if e.matchAny(ips, m) {
			return true, nil, nil
		}
	}
	return false, nil, nil
}

func dropNullMX(hosts []string) []string {
	out := hosts[:0:0]
	for _, h := range hosts {
		if h = normalizeDomain(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func (e *evaluator) evalPTR(target string, here []Step, b *budget, top bool) (bool, []Step, *Error) {
	names, err := e.r.LookupAddr(e.ctx, e.ip)
	if err != nil {
		// RFC 7208 §5.5: a DNS error on the PTR lookup is simply no match.
		if errors.Is(err, ErrNotFound) {
			e.countVoid(here)
		}
		return false, nil, nil
	}
	if len(names) > defaultPTRLimit {
		e.record(ErrPTRLimit, here, nil, "%s has %d PTR names, only the first %d are used", e.ip, len(names), defaultPTRLimit)
		names = names[:defaultPTRLimit]
	}
	for _, n := range names {
		n = normalizeDomain(n)
		if n != target && !strings.HasSuffix(n, "."+target) {
			continue
		}
		if err := e.charge(here, b); err != nil {
			if top {
				return false, nil, nil
			}
			return false, nil, err
		}
		if e.validates(n) {
			return true, nil, nil
		}
	}
	return false, nil, nil
}

func (e *evaluator) evalExists(target string, here []Step) (bool, []Step, *Error) {
	ips, err := e.r.LookupIP(e.ctx, "ip4", target)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			e.countVoid(here)
			return false, nil, nil
		}
		return false, nil, e.record(ErrDNS, here, err, "A %s", target)
	}
	if len(ips) == 0 {
		e.countVoid(here)
	}
	return len(ips) > 0, nil, nil
}

// lookupIP queries A or AAAA records of name, matching the client IP family.
// primary marks the mechanism's own query, which counts toward void lookups.
func (e *evaluator) lookupIP(name string, here []Step, primary bool) ([]netip.Addr, *Error) {
	network := "ip4"
	if e.ip.Is6() {
		network = "ip6"
	}
	ips, err := e.r.LookupIP(e.ctx, network, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if primary {
				e.countVoid(here)
			}
			return nil, nil
		}
		return nil, e.record(ErrDNS, here, err, "%s %s", network, name)
	}
	if len(ips) == 0 && primary {
		e.countVoid(here)
	}
	return ips, nil
}

func (e *evaluator) matchAny(ips []netip.Addr, m Mechanism) bool {
	bits := m.CIDR4
	if e.ip.Is6() {
		bits = m.CIDR6
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() != e.ip.Is4() {
			continue
		}
		if bits < 0 {
			if ip == e.ip {
				return true
			}
			continue
		}
		if p, err := ip.Prefix(bits); err == nil && p.Contains(e.ip) {
			return true
		}
	}
	return false
}

// validates reports whether name resolves back to the client IP (the
// "validated domain name" check of RFC 7208 §5.5).
func (e *evaluator) validates(name string) bool {
	network := "ip4"
	if e.ip.Is6() {
		network = "ip6"
	}
	ips, err := e.r.LookupIP(e.ctx, network, name)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.Unmap() == e.ip {
			return true
		}
	}
	return false
}

// ptrMacro returns the value of %{p} for the current domain.
func (e *evaluator) ptrMacro(domain string) string {
	if !e.validatedDone {
		e.validatedDone = true
		names, err := e.r.LookupAddr(e.ctx, e.ip)
		if err == nil {
			if len(names) > defaultPTRLimit {
				names = names[:defaultPTRLimit]
			}
			for _, n := range names {
				if n = normalizeDomain(n); e.validates(n) {
					e.validatedNames = append(e.validatedNames, n)
				}
			}
		}
	}
	for _, n := range e.validatedNames {
		if n == domain {
			return n
		}
	}
	for _, n := range e.validatedNames {
		if strings.HasSuffix(n, "."+domain) {
			return n
		}
	}
	if len(e.validatedNames) > 0 {
		return e.validatedNames[0]
	}
	return "unknown"
}

// countLookup counts an RFC-limited DNS-mechanism lookup and charges budget b.
func (e *evaluator) countLookup(here []Step, b *budget) *Error {
	e.lookups++
	if e.lookups > e.o.lookupLimit && !e.lookupLimitHit {
		e.lookupLimitHit = true
		e.record(ErrLookupLimit, here, nil, "more than %d DNS lookups", e.o.lookupLimit)
	}
	return e.charge(here, b)
}

// charge takes one lookup from budget b.
func (e *evaluator) charge(here []Step, b *budget) *Error {
	if b.exhausted {
		return &Error{Code: ErrSubtreeBudget}
	}
	if b.left <= 0 {
		b.exhausted = true
		return e.record(ErrSubtreeBudget, here, nil, "more than %d lookups in this subtree", e.o.subtreeBudget)
	}
	b.left--
	return nil
}

func (e *evaluator) countVoid(here []Step) {
	e.voids++
	if e.voids > e.o.voidLimit && !e.voidLimitHit {
		e.voidLimitHit = true
		e.record(ErrVoidLimit, here, nil, "more than %d void lookups", e.o.voidLimit)
	}
}

func (e *evaluator) checkLoop(target string, here []Step) *Error {
	for i, d := range e.active {
		if d == target {
			cycle := append(append([]string(nil), e.active[i:]...), target)
			return e.record(ErrLoop, here, nil, "%s", strings.Join(cycle, " -> "))
		}
	}
	return nil
}

// targetDomain expands a domain-spec in the context of the current domain.
func (e *evaluator) targetDomain(spec, domain string, here []Step) (string, *Error) {
	env := e.env
	env.domain = domain
	env.ptr = func() string { return e.ptrMacro(domain) }
	s, err := expandMacros(spec, &env, false)
	if err != nil {
		return "", e.record(ErrMacro, here, err, "%q", spec)
	}
	return truncateDomain(normalizeDomain(s)), nil
}

// truncateDomain drops leading labels until the name fits in 253 octets
// (RFC 7208 §4.8).
func truncateDomain(d string) string {
	for len(d) > 253 {
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return d
		}
		d = d[i+1:]
	}
	return d
}

// validDomain checks for a well-formed multi-label domain name.
func validDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
	}
	return true
}
