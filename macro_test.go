package spfer

import (
	"net/netip"
	"testing"
	"time"
)

// RFC 7208 §7.4 examples.
func TestMacroRFCExamples(t *testing.T) {
	env := &macroEnv{
		sender:       "strong-bad@email.example.com",
		local:        "strong-bad",
		senderDomain: "email.example.com",
		domain:       "email.example.com",
		helo:         "mx.example.org",
		ip:           netip.MustParseAddr("192.0.2.3"),
		receiver:     "rcv.example.net",
		now:          time.Unix(1700000000, 0),
	}
	tests := map[string]string{
		"%{s}":                              "strong-bad@email.example.com",
		"%{o}":                              "email.example.com",
		"%{d}":                              "email.example.com",
		"%{d4}":                             "email.example.com",
		"%{d3}":                             "email.example.com",
		"%{d2}":                             "example.com",
		"%{d1}":                             "com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l}":                              "strong-bad",
		"%{l-}":                             "strong.bad",
		"%{lr}":                             "strong-bad",
		"%{lr-}":                            "bad.strong",
		"%{l1r-}":                           "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}":   "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
		"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}":  "3.2.0.192.in-addr.strong.lp._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
		"%{h}%%%_%-":                        "mx.example.org% %20",
		"%{S}":                              "strong-bad%40email.example.com",
	}
	for in, want := range tests {
		got, err := expandMacros(in, env, false)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", in, got, err, want)
		}
	}

	exp := map[string]string{
		"%{c} at %{r} %{t}": "192.0.2.3 at rcv.example.net 1700000000",
	}
	for in, want := range exp {
		got, err := expandMacros(in, env, true)
		if err != nil || got != want {
			t.Errorf("%s = %q, %v; want %q", in, got, err, want)
		}
	}

	env.ip = netip.MustParseAddr("2001:db8::cb01")
	got, _ := expandMacros("%{ir}.%{v}._spf.%{d2}", env, false)
	if want := "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"; got != want {
		t.Errorf("ipv6 = %q, want %q", got, want)
	}
}

func TestMacroInvalid(t *testing.T) {
	for _, in := range []string{"%{c}", "%{r}", "%{t}", "%{x}", "%{d0}", "%{d", "%", "%a", "%{d*}", "%{}", "a b"} {
		if err := validateMacroString(in, false); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}
