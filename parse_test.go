package spfer

import (
	"errors"
	"net/netip"
	"testing"
)

func TestParseValid(t *testing.T) {
	rec, err := Parse("v=spf1 +a -mx:mail.example.com/24//64 ~ptr ?ip4:192.0.2.7/24 ip6:2001:db8::/32 " +
		"include:_spf.example.com exists:%{i}._spf.%{d} all redirect=_spf.example.net exp=exp.%{d} foo=bar")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Mechanisms) != 8 || len(rec.Modifiers) != 3 {
		t.Fatalf("got %d mechanisms, %d modifiers", len(rec.Mechanisms), len(rec.Modifiers))
	}
	m := rec.Mechanisms
	if m[0].Kind != KindA || m[0].Qualifier != QualPass || m[0].Domain != "" || m[0].CIDR4 != -1 {
		t.Errorf("a = %+v", m[0])
	}
	if m[1].Kind != KindMX || m[1].Qualifier != QualFail || m[1].Domain != "mail.example.com" || m[1].CIDR4 != 24 || m[1].CIDR6 != 64 {
		t.Errorf("mx = %+v", m[1])
	}
	if m[2].Kind != KindPTR || m[2].Qualifier != QualSoftFail {
		t.Errorf("ptr = %+v", m[2])
	}
	if m[3].Prefix != netip.MustParsePrefix("192.0.2.0/24") || m[3].Qualifier != QualNeutral {
		t.Errorf("ip4 = %+v", m[3])
	}
	if m[4].Prefix != netip.MustParsePrefix("2001:db8::/32") {
		t.Errorf("ip6 = %+v", m[4])
	}
	if m[7].Kind != KindAll || m[7].Index != 7 {
		t.Errorf("all = %+v", m[7])
	}
	if rec.Redirect == nil || rec.Redirect.Value != "_spf.example.net" || rec.Redirect.Index != 8 {
		t.Errorf("redirect = %+v", rec.Redirect)
	}
	if rec.Exp == nil || rec.Exp.Value != "exp.%{d}" {
		t.Errorf("exp = %+v", rec.Exp)
	}
}

func TestParseInvalid(t *testing.T) {
	for _, rec := range []string{
		"v=spf2 -all",
		"v=spf1x -all",
		"v=spf1 all:foo",
		"v=spf1 include",
		"v=spf1 include:",
		"v=spf1 include:localhost",
		"v=spf1 a:example.123",
		"v=spf1 ip4:300.0.0.1",
		"v=spf1 ip4:192.0.2.1/33",
		"v=spf1 ip4:192.0.2.1/024",
		"v=spf1 ip4:2001:db8::1",
		"v=spf1 ip6:192.0.2.1",
		"v=spf1 ip6:2001:db8::/129",
		"v=spf1 a/33",
		"v=spf1 a//129",
		"v=spf1 foo:bar",
		"v=spf1 redirect=a.example redirect=b.example",
		"v=spf1 exp=a.example exp=b.example",
		"v=spf1 exists:%{z}.example.com",
		"v=spf1 1foo=bar",
	} {
		_, err := Parse(rec)
		if err == nil {
			t.Errorf("%q: expected error", rec)
			continue
		}
		if !errors.Is(err, ErrSyntax) {
			t.Errorf("%q: error %v is not ErrSyntax", rec, err)
		}
	}
}
