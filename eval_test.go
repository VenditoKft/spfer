package spfer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

var clientIP = netip.MustParseAddr("192.0.2.1")

func check(t *testing.T, zone map[string][]rr, domain string, opts ...Option) *CheckResult {
	t.Helper()
	opts = append([]Option{WithResolver(newMock(zone))}, opts...)
	return Check(context.Background(), clientIP, domain, opts...)
}

func wantResults(t *testing.T, res *CheckResult, strict, effective Result) {
	t.Helper()
	if res.Result != strict || res.EffectiveResult != effective {
		t.Fatalf("Result=%s EffectiveResult=%s, want %s/%s\nerrors: %v",
			res.Result, res.EffectiveResult, strict, effective, res.Errors)
	}
}

func wantChain(t *testing.T, res *CheckResult, terms ...string) {
	t.Helper()
	if res.Match == nil {
		t.Fatalf("Match = nil, want %v", terms)
	}
	got := make([]string, len(res.Match.Chain))
	for i, s := range res.Match.Chain {
		got[i] = s.Term
	}
	if strings.Join(got, " | ") != strings.Join(terms, " | ") {
		t.Fatalf("chain = %v, want %v", got, terms)
	}
}

func wantError(t *testing.T, res *CheckResult, code ErrorCode) *Error {
	t.Helper()
	for _, e := range res.Errors {
		if errors.Is(e, code) {
			return e
		}
	}
	t.Fatalf("no %v error in %v", code, res.Errors)
	return nil
}

func wantNoErrors(t *testing.T, res *CheckResult) {
	t.Helper()
	if len(res.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", res.Errors)
	}
}

func TestPassChain(t *testing.T) {
	zone := map[string][]rr{
		"example.com":            {txt("v=spf1 ip4:198.51.100.0/24 include:_spf.example.net -all")},
		"_spf.example.net":       {txt("v=spf1 include:_netblocks.example.net ~all")},
		"_netblocks.example.net": {txt("v=spf1 ip4:203.0.113.0/24 ip4:192.0.2.0/25 ?all")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, Pass, Pass)
	wantNoErrors(t, res)
	wantChain(t, res, "include:_spf.example.net", "include:_netblocks.example.net", "ip4:192.0.2.0/25")
	top, leaf := res.Match.Top(), res.Match.Leaf()
	if top.Domain != "example.com" || top.Index != 1 || top.Kind != KindInclude {
		t.Errorf("top = %+v", top)
	}
	if leaf.Domain != "_netblocks.example.net" || leaf.Index != 1 || leaf.Kind != KindIP4 || leaf.Qualifier != QualPass {
		t.Errorf("leaf = %+v", leaf)
	}
	if res.Lookups != 2 {
		t.Errorf("Lookups = %d, want 2", res.Lookups)
	}
}

func TestFailMatchesAll(t *testing.T) {
	zone := map[string][]rr{"example.com": {txt("v=spf1 ip4:198.51.100.1 ~all")}}
	res := check(t, zone, "example.com")
	wantResults(t, res, SoftFail, SoftFail)
	wantChain(t, res, "~all")
}

func TestNoRecordAndDefaultNeutral(t *testing.T) {
	zone := map[string][]rr{
		"none.example":    {txt("google-site-verification=x")},
		"neutral.example": {txt("v=spf1 ip4:198.51.100.1")},
	}
	res := check(t, zone, "none.example")
	wantResults(t, res, None, None)
	if res.Match != nil {
		t.Error("Match should be nil")
	}
	res = check(t, zone, "neutral.example")
	wantResults(t, res, Neutral, Neutral)
	if res.Match != nil {
		t.Error("Match should be nil")
	}
}

func TestLookupLimitSoft(t *testing.T) {
	zone := map[string][]rr{}
	var terms []string
	for i := 1; i <= 11; i++ {
		d := fmt.Sprintf("i%d.example", i)
		terms = append(terms, "include:"+d)
		zone[d] = []rr{txt("v=spf1 -all")}
	}
	zone["i11.example"] = []rr{txt("v=spf1 ip4:192.0.2.1 -all")}
	zone["example.com"] = []rr{txt("v=spf1 " + strings.Join(terms, " ") + " -all")}

	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, Pass)
	wantChain(t, res, "include:i11.example", "ip4:192.0.2.1")
	e := wantError(t, res, ErrLookupLimit)
	if e.Chain[0].Term != "include:i11.example" {
		t.Errorf("limit recorded at %v, want the 11th include", e.Chain)
	}
	if res.Lookups != 11 {
		t.Errorf("Lookups = %d, want 11", res.Lookups)
	}
	if len(res.Errors) != 1 {
		t.Errorf("limit should be recorded once, got %v", res.Errors)
	}
}

func TestLookupLimitNotReachedBeforeMatch(t *testing.T) {
	zone := map[string][]rr{}
	var terms []string
	for i := 1; i <= 15; i++ {
		d := fmt.Sprintf("i%d.example", i)
		terms = append(terms, "include:"+d)
		zone[d] = []rr{txt("v=spf1 ip4:192.0.2.1 -all")}
	}
	zone["example.com"] = []rr{txt("v=spf1 " + strings.Join(terms, " ") + " -all")}
	res := check(t, zone, "example.com")
	wantResults(t, res, Pass, Pass)
	wantNoErrors(t, res)
	if res.Lookups != 1 {
		t.Errorf("Lookups = %d, want 1 (stop at first match)", res.Lookups)
	}
}

func TestVoidLimitSoft(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 a:v1.example a:v2.example exists:v3.example ip4:192.0.2.1 -all")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, Pass)
	wantChain(t, res, "ip4:192.0.2.1")
	wantError(t, res, ErrVoidLimit)
	if res.VoidLookups != 3 {
		t.Errorf("VoidLookups = %d, want 3", res.VoidLookups)
	}
}

func TestMXLimitSoft(t *testing.T) {
	zone := map[string][]rr{"example.com": {txt("v=spf1 mx -all")}}
	var mxs []rr
	for i := 1; i <= 12; i++ {
		h := fmt.Sprintf("mx%d.example.com", i)
		mxs = append(mxs, mx(h))
		zone[h] = []rr{a(fmt.Sprintf("198.51.100.%d", i))}
	}
	zone["example.com"] = append(zone["example.com"], mxs...)
	zone["mx12.example.com"] = []rr{a("192.0.2.1")}

	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, Pass)
	wantChain(t, res, "mx")
	wantError(t, res, ErrMXLimit)
}

func TestPTRLimitInformational(t *testing.T) {
	zone := map[string][]rr{"example.com": {txt("v=spf1 ptr -all")}}
	var ptrs []rr
	for i := 1; i <= 12; i++ {
		ptrs = append(ptrs, ptr(fmt.Sprintf("h%d.other.example", i)))
	}
	ptrs = append(ptrs, ptr("mail.example.com"))
	zone["1.2.0.192.in-addr.arpa"] = ptrs
	zone["mail.example.com"] = []rr{a("192.0.2.1")}

	res := check(t, zone, "example.com")
	// Per RFC 7208 §4.6.4 names beyond the 10th are ignored, not an error.
	wantResults(t, res, Fail, Fail)
	wantError(t, res, ErrPTRLimit)
}

func TestSubtreeBudgetPerTopLevelInclude(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:deep0.example include:ok.example -all")},
		"ok.example":  {txt("v=spf1 include:ok2.example -all")},
		"ok2.example": {txt("v=spf1 ip4:192.0.2.1 -all")},
	}
	for i := 0; i < 40; i++ {
		zone[fmt.Sprintf("deep%d.example", i)] = []rr{txt(fmt.Sprintf("v=spf1 include:deep%d.example -all", i+1))}
	}

	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, Pass)
	wantChain(t, res, "include:ok.example", "include:ok2.example", "ip4:192.0.2.1")
	e := wantError(t, res, ErrSubtreeBudget)
	if e.Chain[0].Term != "include:deep0.example" || len(e.Chain) != 26 {
		t.Errorf("budget error chain: top %q, depth %d (want deep0, 26)", e.Chain[0].Term, len(e.Chain))
	}
	wantError(t, res, ErrLookupLimit)
	if res.Lookups != 25+1+2 {
		t.Errorf("Lookups = %d, want 28", res.Lookups)
	}
}

func TestSubtreeBudgetConfigurable(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:a.example ip4:192.0.2.1 -all")},
		"a.example":   {txt("v=spf1 include:b.example -all")},
		"b.example":   {txt("v=spf1 include:c.example -all")},
		"c.example":   {txt("v=spf1 -all")},
	}
	res := check(t, zone, "example.com", WithSubtreeBudget(2))
	wantResults(t, res, PermError, Pass)
	wantChain(t, res, "ip4:192.0.2.1")
	wantError(t, res, ErrSubtreeBudget)
}

func TestRootBudget(t *testing.T) {
	var terms []string
	for i := 0; i < 30; i++ {
		terms = append(terms, fmt.Sprintf("a:h%d.example.com", i))
	}
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 " + strings.Join(terms, " ") + " include:x.example -all")},
		"x.example":   {txt("v=spf1 ip4:192.0.2.1")},
	}
	for i := 0; i < 30; i++ {
		zone[fmt.Sprintf("h%d.example.com", i)] = []rr{a("198.51.100.1")}
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, Pass)
	wantChain(t, res, "include:x.example", "ip4:192.0.2.1")
	wantError(t, res, ErrSubtreeBudget)
	if res.Lookups != 26+1 {
		t.Errorf("Lookups = %d, want 27 (25 + the over-budget attempt + include)", res.Lookups)
	}
}

func TestIncludeLoop(t *testing.T) {
	zone := map[string][]rr{
		"a.example": {txt("v=spf1 include:b.example -all")},
		"b.example": {txt("v=spf1 include:A.example. -all")},
	}
	res := check(t, zone, "a.example")
	wantResults(t, res, PermError, PermError)
	e := wantError(t, res, ErrLoop)
	if !strings.Contains(e.Msg, "a.example -> b.example -> a.example") {
		t.Errorf("loop message = %q", e.Msg)
	}
	if res.Match != nil {
		t.Error("Match should be nil")
	}
}

func TestRedirectLoop(t *testing.T) {
	zone := map[string][]rr{
		"a.example": {txt("v=spf1 redirect=b.example")},
		"b.example": {txt("v=spf1 redirect=a.example")},
	}
	res := check(t, zone, "a.example")
	wantResults(t, res, PermError, PermError)
	wantError(t, res, ErrLoop)
}

func TestSiblingIncludesAreNotLoops(t *testing.T) {
	zone := map[string][]rr{
		"example.com":    {txt("v=spf1 include:x.example include:y.example -all")},
		"x.example":      {txt("v=spf1 include:shared.example -all")},
		"y.example":      {txt("v=spf1 include:shared.example ip4:192.0.2.1 -all")},
		"shared.example": {txt("v=spf1 ip4:198.51.100.1 -all")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, Pass, Pass)
	wantNoErrors(t, res)
	wantChain(t, res, "include:y.example", "ip4:192.0.2.1")
}

func TestTempErrorInInclude(t *testing.T) {
	zone := map[string][]rr{
		"example.com":  {txt("v=spf1 include:slow.example ip4:192.0.2.1 -all")},
		"slow.example": {timeout},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, TempError, TempError)
	e := wantError(t, res, ErrDNS)
	if e.Chain[0].Term != "include:slow.example" {
		t.Errorf("chain = %v", e.Chain)
	}
}

func TestTempErrorAfterSoftBreach(t *testing.T) {
	zone := map[string][]rr{
		"example.com":  {txt("v=spf1 a:v1.example a:v2.example a:v3.example include:slow.example -all")},
		"slow.example": {timeout},
	}
	res := check(t, zone, "example.com")
	// RFC evaluation would have stopped at the void limit.
	wantResults(t, res, PermError, TempError)
}

func TestNestedSyntaxErrorIsHard(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 include:bad.example ip4:192.0.2.1 -all")},
		"bad.example": {txt("v=spf1 ip4:300.1.1.1 -all")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, PermError)
	e := wantError(t, res, ErrSyntax)
	if e.Chain[0].Term != "include:bad.example" {
		t.Errorf("chain = %v", e.Chain)
	}
}

func TestIncludeWithoutRecord(t *testing.T) {
	zone := map[string][]rr{
		"example.com":   {txt("v=spf1 include:empty.example -all")},
		"empty.example": {a("192.0.2.1")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, PermError)
	wantError(t, res, ErrNoRecord)
}

func TestMultipleRecords(t *testing.T) {
	zone := map[string][]rr{"example.com": {txt("v=spf1 -all"), txt("v=spf1 +all")}}
	res := check(t, zone, "example.com")
	wantResults(t, res, PermError, PermError)
	wantError(t, res, ErrMultipleRecords)
}

func TestRedirectChain(t *testing.T) {
	zone := map[string][]rr{
		"example.com":      {txt("v=spf1 ip4:198.51.100.1 redirect=_spf.example.com")},
		"_spf.example.com": {txt("v=spf1 include:x.example -all")},
		"x.example":        {txt("v=spf1 ip4:192.0.2.0/24")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, Pass, Pass)
	wantChain(t, res, "redirect=_spf.example.com", "include:x.example", "ip4:192.0.2.0/24")
	if k := res.Match.Top().Kind; k != KindRedirect {
		t.Errorf("top kind = %v", k)
	}
}

func TestCacheHitsStillCount(t *testing.T) {
	zone := map[string][]rr{"example.com": {txt("v=spf1 a a a ip4:192.0.2.1"), a("198.51.100.1")}}
	m := newMock(zone)
	res := Check(context.Background(), clientIP, "example.com", WithResolver(m))
	wantResults(t, res, Pass, Pass)
	if res.Lookups != 3 {
		t.Errorf("Lookups = %d, want 3", res.Lookups)
	}
	if n := m.queries["A example.com"]; n != 1 {
		t.Errorf("A example.com queried %d times, want 1", n)
	}
}

func TestCheckDefaultsSenderAndHelo(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 exists:%{l}.%{o}.%{h}._spf.%{d} -all")},
		"postmaster.example.com.example.com._spf.example.com": {a("127.0.0.2")},
	}
	res := check(t, zone, "example.com")
	wantResults(t, res, Pass, Pass)
	wantChain(t, res, "exists:%{l}.%{o}.%{h}._spf.%{d}")
}

func TestCheckHostUsesSender(t *testing.T) {
	zone := map[string][]rr{
		"example.com":                      {txt("v=spf1 exists:%{l}.%{i}._spf.%{d} -all")},
		"alice.192.0.2.1._spf.example.com": {a("127.0.0.2")},
	}
	res := CheckHost(context.Background(), clientIP, "example.com", "alice@example.com", "mx.example.org",
		WithResolver(newMock(zone)))
	wantResults(t, res, Pass, Pass)
	res = CheckHost(context.Background(), clientIP, "example.com", "bob@example.com", "mx.example.org",
		WithResolver(newMock(zone)))
	wantResults(t, res, Fail, Fail)
}

func TestExplanation(t *testing.T) {
	zone := map[string][]rr{
		"example.com":     {txt("v=spf1 -all exp=exp.example.com")},
		"exp.example.com": {txt("%{i} is not allowed to send for %{d}")},
	}
	res := check(t, zone, "example.com")
	if res.Explanation != "" {
		t.Errorf("explanation fetched without option: %q", res.Explanation)
	}
	res = check(t, zone, "example.com", WithExplanation())
	if want := "192.0.2.1 is not allowed to send for example.com"; res.Explanation != want {
		t.Errorf("Explanation = %q, want %q", res.Explanation, want)
	}
	if res.Lookups != 0 {
		t.Errorf("exp lookup counted: %d", res.Lookups)
	}
}

func TestIPv6AndMapped(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 ip6:2001:db8::/32 a/24 -all"), a("198.51.100.7")},
	}
	m := newMock(zone)
	res := Check(context.Background(), netip.MustParseAddr("2001:db8::25"), "example.com", WithResolver(m))
	wantResults(t, res, Pass, Pass)
	wantChain(t, res, "ip6:2001:db8::/32")

	res = Check(context.Background(), netip.MustParseAddr("::ffff:198.51.100.200"), "example.com", WithResolver(m))
	wantResults(t, res, Pass, Pass)
	wantChain(t, res, "a/24")
}

func TestErrorsIs(t *testing.T) {
	err := &Error{Code: ErrLoop, Msg: "x", Err: ErrNotFound}
	if !errors.Is(err, ErrLoop) || errors.Is(err, ErrSyntax) || !errors.Is(err, ErrNotFound) {
		t.Error("errors.Is mismatch")
	}
	if !strings.Contains(err.Error(), "include loop detected: x") {
		t.Errorf("Error() = %q", err.Error())
	}
}

func TestSubtreeBudgetOnTopLevelRedirect(t *testing.T) {
	zone := map[string][]rr{
		"example.com": {txt("v=spf1 ip4:198.51.100.1 redirect=deep0.example")},
	}
	for i := 0; i < 40; i++ {
		zone[fmt.Sprintf("deep%d.example", i)] = []rr{txt(fmt.Sprintf("v=spf1 include:deep%d.example -all", i+1))}
	}
	res := check(t, zone, "example.com")
	// The redirect is treated as not evaluated: default neutral.
	wantResults(t, res, PermError, Neutral)
	wantError(t, res, ErrSubtreeBudget)
}
