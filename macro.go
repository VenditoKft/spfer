package spfer

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// macroEnv holds the values macros expand to (RFC 7208 §7.2).
type macroEnv struct {
	sender       string // <sender>, always local@domain
	local        string // local-part of sender
	senderDomain string // domain of sender
	domain       string // current <domain>
	helo         string
	ip           netip.Addr
	receiver     string
	now          time.Time
	ptr          func() string // validated domain name of ip, for %{p}
}

// validateMacroString checks macro-string syntax without expanding it.
func validateMacroString(s string, exp bool) error {
	_, err := expandMacros(s, nil, exp)
	return err
}

// expandMacros expands a macro-string. With exp set, the explanation-only
// letters c, r, t are allowed and spaces are literal. A nil env only validates.
func expandMacros(s string, env *macroEnv, exp bool) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			if !exp && (c < 0x21 || c > 0x7e) {
				return "", fmt.Errorf("invalid character %q in macro-string", c)
			}
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("trailing %% in %q", s)
		}
		switch s[i] {
		case '%':
			b.WriteByte('%')
		case '_':
			b.WriteByte(' ')
		case '-':
			b.WriteString("%20")
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated macro in %q", s)
			}
			v, err := expandMacro(s[i+1:i+end], env, exp)
			if err != nil {
				return "", err
			}
			b.WriteString(v)
			i += end
		default:
			return "", fmt.Errorf("invalid macro escape %%%c in %q", s[i], s)
		}
	}
	return b.String(), nil
}

// expandMacro expands the inside of one %{...} macro.
func expandMacro(m string, env *macroEnv, exp bool) (string, error) {
	if m == "" {
		return "", fmt.Errorf("empty macro")
	}
	letter := m[0]
	upper := letter >= 'A' && letter <= 'Z'
	lower := letter | 0x20
	switch lower {
	case 's', 'l', 'o', 'd', 'i', 'p', 'v', 'h':
	case 'c', 'r', 't':
		if !exp {
			return "", fmt.Errorf("macro %%{%c} is only allowed in explanations", letter)
		}
	default:
		return "", fmt.Errorf("unknown macro letter %q", letter)
	}

	rest := m[1:]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	keep := 0
	if j > 0 {
		n, err := strconv.Atoi(rest[:j])
		if err != nil || n == 0 {
			return "", fmt.Errorf("invalid digit transformer in %%{%s}", m)
		}
		keep = n
	}
	rest = rest[j:]
	reverse := false
	if rest != "" && (rest[0] == 'r' || rest[0] == 'R') {
		reverse = true
		rest = rest[1:]
	}
	delims := rest
	for k := 0; k < len(delims); k++ {
		if !strings.ContainsRune(".-+,/_=", rune(delims[k])) {
			return "", fmt.Errorf("invalid delimiter %q in %%{%s}", delims[k], m)
		}
	}
	if env == nil {
		return "", nil
	}

	value := env.value(lower)
	if delims == "" {
		delims = "."
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(delims, r) })
	if delims != "." || keep > 0 || reverse {
		// Splitting is only observable when transformers or delimiters are
		// used; otherwise keep the value byte-for-byte.
		if reverse {
			for a, z := 0, len(parts)-1; a < z; a, z = a+1, z-1 {
				parts[a], parts[z] = parts[z], parts[a]
			}
		}
		if keep > 0 && keep < len(parts) {
			parts = parts[len(parts)-keep:]
		}
		value = strings.Join(parts, ".")
	}
	if upper {
		value = urlEscape(value)
	}
	return value, nil
}

func (e *macroEnv) value(letter byte) string {
	switch letter {
	case 's':
		return e.sender
	case 'l':
		return e.local
	case 'o':
		return e.senderDomain
	case 'd':
		return e.domain
	case 'i':
		return dottedIP(e.ip)
	case 'p':
		if e.ptr == nil {
			return "unknown"
		}
		return e.ptr()
	case 'v':
		if e.ip.Is4() {
			return "in-addr"
		}
		return "ip6"
	case 'h':
		return e.helo
	case 'c':
		return e.ip.String()
	case 'r':
		return e.receiver
	case 't':
		return strconv.FormatInt(e.now.Unix(), 10)
	}
	return ""
}

// dottedIP formats an address for %{i}: dotted quad for IPv4, dot-separated
// nibbles for IPv6.
func dottedIP(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String()
	}
	const hex = "0123456789abcdef"
	a := ip.As16()
	var b strings.Builder
	for k, x := range a {
		if k > 0 {
			b.WriteByte('.')
		}
		b.WriteByte(hex[x>>4])
		b.WriteByte('.')
		b.WriteByte(hex[x&0xf])
	}
	return b.String()
}

func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}
