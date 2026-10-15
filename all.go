package spfer

import (
	"context"
	"net/netip"
)

// CheckAll is like Check, but also fills CheckResult.Matches with every
// directive chain that matches ip. See CheckHostAll.
func CheckAll(ctx context.Context, ip netip.Addr, domain string, opts ...Option) *CheckResult {
	return CheckHostAll(ctx, ip, domain, "", "", opts...)
}

// CheckHostAll is like CheckHost, but evaluation does not stop at the first
// match: CheckResult.Matches lists every directive chain whose leaf mechanism
// matches ip, whatever its qualifier, in record order. The all mechanism is
// not reported. A redirect is followed only when no mechanism of its record
// matched and the record has no all mechanism.
//
// All other fields are exactly what CheckHost returns. Collecting the matches
// is best-effort: a subtree that ends in an error is skipped, and its errors
// are not added to Errors. DNS answers are shared with the regular evaluation,
// so no query is repeated.
func CheckHostAll(ctx context.Context, ip netip.Addr, domain, sender, helo string, opts ...Option) *CheckResult {
	res, e := checkHost(ctx, ip, domain, sender, helo, newOptions(opts))
	if e == nil {
		return res
	}
	c := &evaluator{ctx: e.ctx, o: e.o, r: e.r, ip: e.ip, env: e.env}
	for _, chain := range c.collect(normalizeDomain(domain), nil, c.newBudget(), true) {
		res.Matches = append(res.Matches, &Match{Chain: chain})
	}
	return res
}

// collect returns every match chain of domain's record, following the rules
// of CheckHostAll. Its arguments are those of checkHost.
func (e *evaluator) collect(domain string, chain []Step, b *budget, top bool) [][]Step {
	e.active = append(e.active, domain)
	defer func() { e.active = e.active[:len(e.active)-1] }()

	rec, _, _ := e.fetchRecord(domain, chain, !top)
	if rec == nil {
		return nil
	}

	var out [][]Step
	hasAll := false
	for _, m := range rec.Mechanisms {
		step := Step{Domain: domain, Term: m.Raw, Index: m.Index, Qualifier: m.Qualifier, Kind: m.Kind}
		here := appendStep(chain, step)
		switch m.Kind {
		case KindAll:
			hasAll = true
		case KindInclude:
			ib := b
			if top {
				ib = e.newBudget()
			}
			if target, ok := e.follow(m.Domain, domain, here, ib); ok {
				out = append(out, e.collect(target, here, ib, false)...)
			}
		default:
			if matched, _, err := e.evalMechanism(m, domain, here, b, top); err == nil && matched {
				out = append(out, here)
			}
		}
	}

	if len(out) > 0 || hasAll || rec.Redirect == nil {
		return out
	}
	mod := rec.Redirect
	here := appendStep(chain, Step{Domain: domain, Term: mod.Raw, Index: mod.Index, Kind: KindRedirect})
	rb := b
	if top {
		rb = e.newBudget()
	}
	if target, ok := e.follow(mod.Value, domain, here, rb); ok {
		return e.collect(target, here, rb, false)
	}
	return nil
}

// follow counts the lookup of an include or redirect and expands its target.
// ok is false when the target must not be evaluated.
func (e *evaluator) follow(spec, domain string, here []Step, b *budget) (string, bool) {
	if err := e.countLookup(here, b); err != nil {
		return "", false
	}
	target, err := e.targetDomain(spec, domain, here)
	if err != nil {
		return "", false
	}
	if err := e.checkLoop(target, here); err != nil {
		return "", false
	}
	return target, true
}
