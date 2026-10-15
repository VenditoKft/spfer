package spfer

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// Check evaluates the SPF record of domain for ip without sender information.
// The sender defaults to postmaster@<domain> and the HELO name to <domain>,
// so every macro still expands.
func Check(ctx context.Context, ip netip.Addr, domain string, opts ...Option) *CheckResult {
	return CheckHost(ctx, ip, domain, "", "", opts...)
}

// CheckHost implements RFC 7208 check_host(): it evaluates the SPF record of
// domain for ip, with sender (MAIL FROM) and helo used for macro expansion.
// An empty sender defaults to postmaster@<domain>, a sender without a local
// part gets "postmaster", and an empty helo defaults to <domain>.
func CheckHost(ctx context.Context, ip netip.Addr, domain, sender, helo string, opts ...Option) *CheckResult {
	res, _ := checkHost(ctx, ip, domain, sender, helo, newOptions(opts))
	return res
}

// checkHost runs CheckHost and also returns the evaluator, or nil when ip is
// invalid.
func checkHost(ctx context.Context, ip netip.Addr, domain, sender, helo string, o *options) (*CheckResult, *evaluator) {
	ip = ip.Unmap()
	res := &CheckResult{}
	if !ip.IsValid() {
		res.Result, res.EffectiveResult = PermError, PermError
		res.Errors = []*Error{{Code: ErrInvalidDomain, Msg: "invalid client IP"}}
		return res, nil
	}

	domain = normalizeDomain(domain)
	r := newCachingResolver(o.resolver, o.queryTimeout)
	e := newEvaluator(ctx, o, r, ip, domain, sender, helo)
	eff, chain, _ := e.checkHost(domain, nil, e.newBudget(), true, true)
	res.EffectiveResult = eff
	res.Result = eff
	if e.soft {
		res.Result = PermError
	}
	if chain != nil && eff != PermError && eff != TempError {
		res.Match = &Match{Chain: chain}
	}
	if eff == Fail && o.explanation && e.exp != nil {
		res.Explanation = e.explain()
	}
	res.Errors = e.errs
	res.Lookups = e.lookups
	res.VoidLookups = e.voids
	return res, e
}

// newEvaluator prepares the evaluation of domain (already normalized) for ip
// (already unmapped).
func newEvaluator(ctx context.Context, o *options, r *cachingResolver, ip netip.Addr, domain, sender, helo string) *evaluator {
	if helo == "" {
		helo = domain
	}
	local, senderDomain := splitSender(sender, domain)
	return &evaluator{
		ctx: ctx,
		o:   o,
		r:   r,
		ip:  ip,
		env: macroEnv{
			sender:       local + "@" + senderDomain,
			local:        local,
			senderDomain: senderDomain,
			helo:         helo,
			ip:           ip,
			receiver:     o.receivingHost,
			now:          o.now(),
		},
	}
}

// splitSender returns the local part and domain of sender, applying the RFC
// 7208 §4.3 defaults.
func splitSender(sender, domain string) (string, string) {
	local, dom := "postmaster", domain
	if sender == "" {
		return local, dom
	}
	if i := strings.LastIndexByte(sender, '@'); i >= 0 {
		if i > 0 {
			local = sender[:i]
		}
		if d := sender[i+1:]; d != "" {
			dom = d
		}
		return local, normalizeDomain(dom)
	}
	return local, normalizeDomain(sender)
}

// explain fetches and expands the exp= explanation. Failures yield "".
func (e *evaluator) explain() string {
	env := e.env
	env.domain = e.exp.domain
	env.ptr = func() string { return e.ptrMacro(e.exp.domain) }
	target, err := expandMacros(e.exp.spec, &env, false)
	if err != nil {
		return ""
	}
	target = truncateDomain(normalizeDomain(target))
	if !validDomain(target) {
		return ""
	}
	txts, err := e.r.LookupTXT(e.ctx, target)
	if err != nil || len(txts) != 1 {
		if err != nil && !errors.Is(err, ErrNotFound) {
			e.record(ErrDNS, nil, err, "exp TXT %s", target)
		}
		return ""
	}
	s, err := expandMacros(txts[0], &env, true)
	if err != nil {
		return ""
	}
	return s
}
