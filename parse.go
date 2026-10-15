package spfer

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Record is a parsed SPF record.
type Record struct {
	Mechanisms []Mechanism
	Redirect   *Modifier  // redirect= modifier, if present
	Exp        *Modifier  // exp= modifier, if present
	Modifiers  []Modifier // every modifier in order, including unknown ones
}

// Mechanism is one mechanism of a record.
type Mechanism struct {
	Index     int    // position among all terms of the record
	Raw       string // term as written
	Qualifier Qualifier
	Kind      Kind
	// Domain is the unexpanded domain-spec. Empty means the current domain
	// (a, mx, ptr without an argument).
	Domain string
	// Prefix is the network of ip4/ip6 mechanisms.
	Prefix netip.Prefix
	// CIDR4 and CIDR6 are the dual-cidr lengths of a/mx; -1 when absent.
	CIDR4, CIDR6 int
}

// Modifier is a name=value term.
type Modifier struct {
	Index int
	Raw   string
	Name  string // lower-cased
	Value string // unexpanded macro-string
}

var (
	modifierRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]*)=(.*)$`)
	cidr6Re    = regexp.MustCompile(`//([0-9]+)$`)
	cidr4Re    = regexp.MustCompile(`/([0-9]+)$`)
)

// isSPFRecord reports whether a TXT string is an SPF version 1 record.
func isSPFRecord(txt string) bool {
	return len(txt) >= 6 && strings.EqualFold(txt[:6], "v=spf1") && (len(txt) == 6 || txt[6] == ' ')
}

// Parse parses an SPF record ("v=spf1 ..."). Errors are *Error with code
// ErrSyntax.
func Parse(record string) (*Record, error) {
	if !isSPFRecord(record) {
		return nil, syntaxErr("record does not start with v=spf1")
	}
	rec := &Record{}
	index := 0
	for _, term := range strings.Split(record[6:], " ") {
		if term == "" {
			continue
		}
		if err := rec.addTerm(term, index); err != nil {
			return nil, err
		}
		index++
	}
	return rec, nil
}

func syntaxErr(format string, args ...any) *Error {
	return &Error{Code: ErrSyntax, Msg: fmt.Sprintf(format, args...)}
}

func (rec *Record) addTerm(term string, index int) error {
	if m := modifierRe.FindStringSubmatch(term); m != nil {
		mod := Modifier{Index: index, Raw: term, Name: strings.ToLower(m[1]), Value: m[2]}
		switch mod.Name {
		case "redirect", "exp":
			if err := validateDomainSpec(mod.Value); err != nil {
				return syntaxErr("%s: %v", term, err)
			}
			slot := &rec.Redirect
			if mod.Name == "exp" {
				slot = &rec.Exp
			}
			if *slot != nil {
				return syntaxErr("duplicate %s modifier", mod.Name)
			}
			*slot = &mod
		default:
			if err := validateMacroString(mod.Value, false); err != nil {
				return syntaxErr("%s: %v", term, err)
			}
		}
		rec.Modifiers = append(rec.Modifiers, mod)
		return nil
	}

	mech, err := parseMechanism(term)
	if err != nil {
		return syntaxErr("%s: %v", term, err)
	}
	mech.Index = index
	rec.Mechanisms = append(rec.Mechanisms, mech)
	return nil
}

func parseMechanism(term string) (Mechanism, error) {
	m := Mechanism{Raw: term, Qualifier: QualPass, CIDR4: -1, CIDR6: -1}
	s := term
	switch s[0] {
	case '+', '-', '~', '?':
		m.Qualifier = Qualifier(s[0])
		s = s[1:]
	}
	name := s
	arg := ""
	if k := strings.IndexAny(s, ":/"); k >= 0 {
		name, arg = s[:k], s[k:]
	}
	switch strings.ToLower(name) {
	case "all":
		m.Kind = KindAll
		if arg != "" {
			return m, fmt.Errorf("all takes no arguments")
		}
	case "include", "exists":
		m.Kind = KindInclude
		if strings.EqualFold(name, "exists") {
			m.Kind = KindExists
		}
		if !strings.HasPrefix(arg, ":") {
			return m, fmt.Errorf("%s requires a domain", name)
		}
		m.Domain = arg[1:]
		if err := validateDomainSpec(m.Domain); err != nil {
			return m, err
		}
	case "a", "mx":
		m.Kind = KindA
		if strings.EqualFold(name, "mx") {
			m.Kind = KindMX
		}
		var err error
		if arg, m.CIDR6, err = cutCIDR(arg, cidr6Re, 128); err != nil {
			return m, err
		}
		if arg, m.CIDR4, err = cutCIDR(arg, cidr4Re, 32); err != nil {
			return m, err
		}
		if arg != "" {
			if !strings.HasPrefix(arg, ":") {
				return m, fmt.Errorf("unexpected %q", arg)
			}
			m.Domain = arg[1:]
			if err := validateDomainSpec(m.Domain); err != nil {
				return m, err
			}
		}
	case "ptr":
		m.Kind = KindPTR
		if arg != "" {
			if !strings.HasPrefix(arg, ":") {
				return m, fmt.Errorf("unexpected %q", arg)
			}
			m.Domain = arg[1:]
			if err := validateDomainSpec(m.Domain); err != nil {
				return m, err
			}
		}
	case "ip4", "ip6":
		v6 := strings.EqualFold(name, "ip6")
		m.Kind = KindIP4
		maxBits := 32
		if v6 {
			m.Kind, maxBits = KindIP6, 128
		}
		if !strings.HasPrefix(arg, ":") {
			return m, fmt.Errorf("%s requires a network", name)
		}
		network, bits, err := cutCIDR(arg[1:], cidr4Re, maxBits)
		if err != nil {
			return m, err
		}
		addr, err := netip.ParseAddr(network)
		if err != nil || addr.Zone() != "" {
			return m, fmt.Errorf("invalid address %q", network)
		}
		if v6 != addr.Is6() || (!v6 && strings.Contains(network, ":")) {
			return m, fmt.Errorf("address %q does not match %s", network, name)
		}
		if bits < 0 {
			bits = maxBits
		}
		m.Prefix = netip.PrefixFrom(addr, bits).Masked()
	default:
		return m, fmt.Errorf("unknown mechanism %q", name)
	}
	return m, nil
}

// cutCIDR removes a trailing cidr-length matched by re from s.
func cutCIDR(s string, re *regexp.Regexp, maxBits int) (string, int, error) {
	loc := re.FindStringSubmatchIndex(s)
	if loc == nil {
		return s, -1, nil
	}
	digits := s[loc[2]:loc[3]]
	n, err := strconv.Atoi(digits)
	if err != nil || n > maxBits || (len(digits) > 1 && digits[0] == '0') {
		return s, -1, fmt.Errorf("invalid cidr length %q", s[loc[0]:])
	}
	return s[:loc[0]], n, nil
}

// validateDomainSpec checks domain-spec = macro-string domain-end, where
// domain-end is "." toplabel ["."] or a macro-expand.
func validateDomainSpec(s string) error {
	if s == "" {
		return fmt.Errorf("empty domain")
	}
	if err := validateMacroString(s, false); err != nil {
		return err
	}
	if endsWithMacroExpand(s) {
		return nil
	}
	t := strings.TrimSuffix(s, ".")
	dot := strings.LastIndexByte(t, '.')
	if dot < 0 {
		return fmt.Errorf("domain %q is not fully qualified", s)
	}
	if !isTopLabel(t[dot+1:]) {
		return fmt.Errorf("invalid top label in %q", s)
	}
	return nil
}

// endsWithMacroExpand reports whether a (syntactically valid) macro-string
// ends with %{...}, %%, %_ or %-.
func endsWithMacroExpand(s string) bool {
	last := false
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			last = false
			continue
		}
		if s[i+1] == '{' {
			i += strings.IndexByte(s[i:], '}')
		} else {
			i++
		}
		last = true
	}
	return last
}

// isTopLabel implements toplabel = ( *alphanum ALPHA *alphanum ) /
// ( 1*alphanum "-" *( alphanum / "-" ) alphanum ).
func isTopLabel(l string) bool {
	if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	alpha, dash := false, false
	for i := 0; i < len(l); i++ {
		c := l[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			alpha = true
		case c >= '0' && c <= '9':
		case c == '-':
			dash = true
		default:
			return false
		}
	}
	return alpha || dash
}
