package spfer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// ErrNotFound must be returned (possibly wrapped) by a Resolver when a name
// does not exist (NXDOMAIN) or has no records of the requested type. Such
// lookups are void lookups. Any other error is treated as a temporary failure.
var ErrNotFound = errors.New("spfer: no such record")

// Resolver performs the DNS queries needed by SPF evaluation.
type Resolver interface {
	// LookupTXT returns the TXT records of name, each record's character
	// strings concatenated.
	LookupTXT(ctx context.Context, name string) ([]string, error)
	// LookupIP returns A (network "ip4") or AAAA (network "ip6") records.
	LookupIP(ctx context.Context, network, name string) ([]netip.Addr, error)
	// LookupMX returns the exchange host names of name's MX records.
	LookupMX(ctx context.Context, name string) ([]string, error)
	// LookupAddr returns the PTR names of addr.
	LookupAddr(ctx context.Context, addr netip.Addr) ([]string, error)
}

// DefaultResolver returns a Resolver backed by net.DefaultResolver.
func DefaultResolver() Resolver { return NetResolver(net.DefaultResolver) }

// NetResolver adapts a *net.Resolver to the Resolver interface.
func NetResolver(r *net.Resolver) Resolver { return netResolver{r} }

type netResolver struct{ r *net.Resolver }

func (n netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txt, err := n.r.LookupTXT(ctx, name)
	return txt, mapNetErr(err)
}

func (n netResolver) LookupIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	ips, err := n.r.LookupNetIP(ctx, network, name)
	if err != nil {
		return nil, mapNetErr(err)
	}
	for i := range ips {
		ips[i] = ips[i].Unmap()
	}
	return ips, nil
}

func (n netResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	mxs, err := n.r.LookupMX(ctx, name)
	if err != nil && len(mxs) == 0 {
		return nil, mapNetErr(err)
	}
	hosts := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		hosts = append(hosts, mx.Host)
	}
	return hosts, nil
}

func (n netResolver) LookupAddr(ctx context.Context, addr netip.Addr) ([]string, error) {
	names, err := n.r.LookupAddr(ctx, addr.String())
	if err != nil && len(names) == 0 {
		return nil, mapNetErr(err)
	}
	return names, nil
}

func mapNetErr(err error) error {
	if err == nil {
		return nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return errors.Join(ErrNotFound, err)
	}
	return err
}

// normalizeDomain lower-cases a domain and strips a trailing dot.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}
