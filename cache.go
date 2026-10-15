package spfer

import (
	"context"
	"net/netip"
	"time"
)

// cachingResolver memoizes queries for the duration of one evaluation and
// applies the per-query timeout. Errors are cached too, so a name that timed
// out is not retried within the same evaluation. Cache hits still count toward
// the SPF limits; counting happens in the evaluator.
type cachingResolver struct {
	r       Resolver
	timeout time.Duration
	txt     map[string]cached[[]string]
	ip      map[string]cached[[]netip.Addr]
	mx      map[string]cached[[]string]
	ptr     map[netip.Addr]cached[[]string]
}

type cached[T any] struct {
	v   T
	err error
}

func newCachingResolver(r Resolver, timeout time.Duration) *cachingResolver {
	return &cachingResolver{
		r:       r,
		timeout: timeout,
		txt:     map[string]cached[[]string]{},
		ip:      map[string]cached[[]netip.Addr]{},
		mx:      map[string]cached[[]string]{},
		ptr:     map[netip.Addr]cached[[]string]{},
	}
}

func lookup[K comparable, T any](ctx context.Context, c *cachingResolver, m map[K]cached[T], key K, f func(context.Context) (T, error)) (T, error) {
	if hit, ok := m[key]; ok {
		return hit.v, hit.err
	}
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	v, err := f(ctx)
	m[key] = cached[T]{v, err}
	return v, err
}

func (c *cachingResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	name = normalizeDomain(name)
	return lookup(ctx, c, c.txt, name, func(ctx context.Context) ([]string, error) {
		return c.r.LookupTXT(ctx, name)
	})
}

func (c *cachingResolver) LookupIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	name = normalizeDomain(name)
	return lookup(ctx, c, c.ip, network+" "+name, func(ctx context.Context) ([]netip.Addr, error) {
		return c.r.LookupIP(ctx, network, name)
	})
}

func (c *cachingResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	name = normalizeDomain(name)
	return lookup(ctx, c, c.mx, name, func(ctx context.Context) ([]string, error) {
		return c.r.LookupMX(ctx, name)
	})
}

func (c *cachingResolver) LookupAddr(ctx context.Context, addr netip.Addr) ([]string, error) {
	return lookup(ctx, c, c.ptr, addr, func(ctx context.Context) ([]string, error) {
		return c.r.LookupAddr(ctx, addr)
	})
}
