package spfer

import (
	"context"
	"strings"
	"testing"
)

func checkAll(t *testing.T, zone map[string][]rr, domain string, opts ...Option) *CheckResult {
	t.Helper()
	opts = append([]Option{WithResolver(newMock(zone))}, opts...)
	return CheckAll(context.Background(), clientIP, domain, opts...)
}

// wantChains compares res.Matches with chains, each given as its terms
// joined by " | ".
func wantChains(t *testing.T, res *CheckResult, chains ...string) {
	t.Helper()
	got := make([]string, len(res.Matches))
	for i, m := range res.Matches {
		terms := make([]string, len(m.Chain))
		for j, s := range m.Chain {
			terms[j] = s.Term
		}
		got[i] = strings.Join(terms, " | ")
	}
	if strings.Join(got, "\n") != strings.Join(chains, "\n") {
		t.Fatalf("matches =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(chains, "\n"))
	}
}

func TestCheckAllIncludeAndIP(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:inc.example ip4:192.0.2.0/24 -all")},
		"inc.example": {txt("v=spf1 ip4:192.0.2.1 -all")},
	}
	res := checkAll(t, zone, "example.com")
	wantResults(t, res, Pass, Pass)
	wantNoErrors(t, res)
	wantChain(t, res, "include:inc.example", "ip4:192.0.2.1")
	wantChains(t, res,
		"include:inc.example | ip4:192.0.2.1",
		"ip4:192.0.2.0/24",
	)

	single := check(t, zone, "example.com")
	if single.Matches != nil {
		t.Errorf("Check set Matches = %v", single.Matches)
	}
	if single.Lookups != res.Lookups || single.Match.String() != res.Match.String() {
		t.Errorf("CheckAll differs from Check: %+v vs %+v", res, single)
	}
}

func TestCheckAllNested(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:a.example ip4:198.51.100.1 ~all")},
		"a.example":   {txt("v=spf1 ip4:192.0.2.0/25 include:b.example ip6:2001:db8::/32 ?all")},
		"b.example":   {txt("v=spf1 ip4:192.0.2.1 ip4:192.0.2.0/30 -all")},
	}
	res := checkAll(t, zone, "example.com")
	wantChains(t, res,
		"include:a.example | ip4:192.0.2.0/25",
		"include:a.example | include:b.example | ip4:192.0.2.1",
		"include:a.example | include:b.example | ip4:192.0.2.0/30",
	)
}

func TestCheckAllSkipsAll(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:inc.example ip4:198.51.100.0/24 -all")},
		"inc.example": {txt("v=spf1 ip4:203.0.113.0/24 ~all")},
	}
	res := checkAll(t, zone, "example.com")
	wantResults(t, res, Fail, Fail)
	wantChains(t, res)
}

func TestCheckAllQualifiers(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:inc.example ?ip4:192.0.2.1 -all")},
		"inc.example": {txt("v=spf1 -ip4:192.0.2.0/24 +all")},
	}
	res := checkAll(t, zone, "example.com")
	wantResults(t, res, Neutral, Neutral)
	wantChains(t, res,
		"include:inc.example | -ip4:192.0.2.0/24",
		"?ip4:192.0.2.1",
	)
	if q := res.Matches[0].Leaf().Qualifier; q != QualFail {
		t.Errorf("leaf qualifier = %q, want -", q)
	}
	if q := res.Matches[1].Leaf().Qualifier; q != QualNeutral {
		t.Errorf("leaf qualifier = %q, want ?", q)
	}
}

func TestCheckAllRedirect(t *testing.T) {
	zone := map[string][]rr{
		"matched.example":   {txt("v=spf1 ip4:192.0.2.1 redirect=target.example")},
		"unmatched.example": {txt("v=spf1 ip4:198.51.100.1 redirect=target.example")},
		"withall.example":   {txt("v=spf1 ip4:198.51.100.1 ~all redirect=target.example")},
		"target.example":    {txt("v=spf1 ip4:192.0.2.0/24 -all")},
	}
	wantChains(t, checkAll(t, zone, "matched.example"), "ip4:192.0.2.1")
	wantChains(t, checkAll(t, zone, "unmatched.example"), "redirect=target.example | ip4:192.0.2.0/24")
	wantChains(t, checkAll(t, zone, "withall.example"))
}

func TestCheckAllSkipsBrokenSubtrees(t *testing.T) {
	zone := map[string][]rr{
		"example.com":  {txt("v=spf1 include:slow.example include:loop.example include:ok.example -all")},
		"slow.example": {timeout},
		"loop.example": {txt("v=spf1 include:example.com ip4:192.0.2.1")},
		"ok.example":   {txt("v=spf1 ip4:192.0.2.1")},
	}
	res := checkAll(t, zone, "example.com")
	wantResults(t, res, TempError, TempError)
	wantChains(t, res,
		"include:loop.example | ip4:192.0.2.1",
		"include:ok.example | ip4:192.0.2.1",
	)
	if len(res.Errors) != 1 {
		t.Errorf("errors = %v, want only the TXT temperror of the regular evaluation", res.Errors)
	}
}

func TestCheckAllDNSMechanismsUseCache(t *testing.T) {
	zone := map[string][]rr{
		"example.com":      {txt("v=spf1 a mx ip4:192.0.2.1 -all"), a("192.0.2.1"), mx("mail.example.com")},
		"mail.example.com": {a("192.0.2.1")},
	}
	mock := newMock(zone)
	res := CheckAll(context.Background(), clientIP, "example.com", WithResolver(mock))
	wantChains(t, res, "a", "mx", "ip4:192.0.2.1")
	for q, n := range mock.queries {
		if n != 1 {
			t.Errorf("%s queried %d times, want 1", q, n)
		}
	}
}
