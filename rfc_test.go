package spfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// suiteDoc is one document of the OpenSPF RFC 7208 test suite.
type suiteDoc struct {
	Description string               `yaml:"description"`
	Tests       map[string]suiteTest `yaml:"tests"`
	Zonedata    map[string][]any     `yaml:"zonedata"`
}

type suiteTest struct {
	Description string `yaml:"description"`
	Spec        any    `yaml:"spec"`
	Helo        string `yaml:"helo"`
	Host        string `yaml:"host"`
	Mailfrom    string `yaml:"mailfrom"`
	Result      any    `yaml:"result"`
	Explanation string `yaml:"explanation"`
}

// TestRFC7208Suite runs testdata/rfc7208-tests.yml (OpenSPF release 2014.04)
// against the strict Result.
func TestRFC7208Suite(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc7208-tests.yml")
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc suiteDoc
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		if doc.Tests == nil {
			continue
		}
		zone, err := suiteZone(doc.Zonedata)
		if err != nil {
			t.Fatalf("%s: %v", doc.Description, err)
		}
		t.Run(doc.Description, func(t *testing.T) {
			for name, tc := range doc.Tests {
				t.Run(name, func(t *testing.T) { runSuiteTest(t, zone, tc) })
			}
		})
	}
}

func runSuiteTest(t *testing.T, zone map[string][]rr, tc suiteTest) {
	ip, err := netip.ParseAddr(tc.Host)
	if err != nil {
		t.Fatal(err)
	}
	domain := tc.Helo
	if i := strings.LastIndexByte(tc.Mailfrom, '@'); i >= 0 {
		domain = tc.Mailfrom[i+1:]
	}
	res := CheckHost(context.Background(), ip, domain, tc.Mailfrom, tc.Helo,
		WithResolver(newMock(zone)), WithExplanation())

	var want []string
	switch r := tc.Result.(type) {
	case string:
		want = []string{r}
	case []any:
		for _, x := range r {
			want = append(want, fmt.Sprint(x))
		}
	}
	if !slices.Contains(want, res.Result.String()) {
		t.Errorf("%s\nresult = %s, want %v (effective %s)\nerrors: %v",
			tc.Description, res.Result, want, res.EffectiveResult, res.Errors)
	}
	// Case-insensitive: the suite expects IPv6 nibbles in the case the address
	// was written in; DNS names are case-insensitive anyway.
	if tc.Explanation != "" && tc.Explanation != "DEFAULT" && res.Result == Fail &&
		!strings.EqualFold(res.Explanation, tc.Explanation) {
		t.Errorf("explanation = %q, want %q", res.Explanation, tc.Explanation)
	}
}

func suiteZone(zd map[string][]any) (map[string][]rr, error) {
	zone := map[string][]rr{}
	for name, entries := range zd {
		var rrs []rr
		for _, entry := range entries {
			switch v := entry.(type) {
			case string:
				rrs = append(rrs, rr{typ: v})
			case map[string]any:
				for typ, val := range v {
					rs, err := suiteRecords(typ, val)
					if err != nil {
						return nil, fmt.Errorf("%s %s: %w", name, typ, err)
					}
					rrs = append(rrs, rs...)
				}
			default:
				return nil, fmt.Errorf("%s: unexpected entry %T", name, entry)
			}
		}
		zone[name] = rrs
	}
	return zone, nil
}

func suiteRecords(typ string, val any) ([]rr, error) {
	list, isList := val.([]any)
	switch {
	case !isList:
		return []rr{{typ, fmt.Sprint(val)}}, nil
	case typ == "TXT" || typ == "SPF":
		var b strings.Builder
		for _, p := range list {
			b.WriteString(fmt.Sprint(p))
		}
		return []rr{{typ, b.String()}}, nil
	case typ == "MX":
		if len(list) != 2 {
			return nil, fmt.Errorf("bad MX %v", list)
		}
		return []rr{{typ, fmt.Sprint(list[1])}}, nil
	}
	var rrs []rr
	for _, x := range list {
		rrs = append(rrs, rr{typ, fmt.Sprint(x)})
	}
	return rrs, nil
}
