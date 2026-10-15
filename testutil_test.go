package spfer

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// rr is one record of the in-memory test zone.
type rr struct {
	typ string // TXT, SPF, A, AAAA, MX, PTR, CNAME, TIMEOUT, SERVFAIL
	val string
}

func txt(s string) rr   { return rr{"TXT", s} }
func a(s string) rr     { return rr{"A", s} }
func aaaa(s string) rr  { return rr{"AAAA", s} }
func mx(s string) rr    { return rr{"MX", s} }
func ptr(s string) rr   { return rr{"PTR", s} }
func cname(s string) rr { return rr{"CNAME", s} }

var timeout = rr{"TIMEOUT", ""}

// mockResolver serves a zone map. Unknown names are NXDOMAIN, known names
// without records of the asked type are NODATA unless they carry TIMEOUT.
// It counts queries per name and type.
type mockResolver struct {
	zone    map[string][]rr
	queries map[string]int
}

func newMock(zone map[string][]rr) *mockResolver {
	z := make(map[string][]rr, len(zone))
	for k, v := range zone {
		z[normalizeDomain(k)] = v
	}
	return &mockResolver{zone: z, queries: map[string]int{}}
}

var errTimeout = errors.New("mock: timeout")

func (m *mockResolver) records(name, typ string) ([]string, error) {
	return m.recordsDepth(normalizeDomain(name), typ, 0)
}

func (m *mockResolver) recordsDepth(name, typ string, depth int) ([]string, error) {
	m.queries[typ+" "+name]++
	rrs, ok := m.zone[name]
	if !ok {
		return nil, ErrNotFound
	}
	var out []string
	hasTXT, hasTimeout := false, false
	for _, r := range rrs {
		switch {
		case r.typ == "TIMEOUT":
			hasTimeout = true
		case r.typ == "SERVFAIL":
			return nil, errors.New("mock: servfail")
		case r.typ == "CNAME" && typ != "CNAME":
			if depth > 8 {
				return nil, errors.New("mock: cname loop")
			}
			return m.recordsDepth(normalizeDomain(r.val), typ, depth+1)
		case r.typ == "TXT" && typ == "TXT":
			hasTXT = true
			if r.val != "NONE" {
				out = append(out, r.val)
			}
		case r.typ == typ:
			out = append(out, r.val)
		}
	}
	if typ == "TXT" && !hasTXT {
		// The test suite publishes most policies as type SPF and expects
		// drivers to serve them as TXT too.
		for _, r := range rrs {
			if r.typ == "SPF" {
				out = append(out, r.val)
			}
		}
	}
	if len(out) == 0 {
		if hasTimeout {
			return nil, errTimeout
		}
		return nil, ErrNotFound
	}
	return out, nil
}

func (m *mockResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return m.records(name, "TXT")
}

func (m *mockResolver) LookupIP(_ context.Context, network, name string) ([]netip.Addr, error) {
	typ := "A"
	if network == "ip6" {
		typ = "AAAA"
	}
	vals, err := m.records(name, typ)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, v := range vals {
		ip, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("mock: bad address %q", v)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func (m *mockResolver) LookupMX(_ context.Context, name string) ([]string, error) {
	return m.records(name, "MX")
}

func (m *mockResolver) LookupAddr(_ context.Context, addr netip.Addr) ([]string, error) {
	return m.records(reverseName(addr), "PTR")
}

func reverseName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	nibbles := strings.Split(dottedIP(ip), ".")
	for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}
	return strings.Join(nibbles, ".") + ".ip6.arpa"
}
