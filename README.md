# spfer

A Go library for evaluating SPF (RFC 7208) records. For a client IP it tells you:

1. **The result**: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror` or `permerror`.
2. **Which directive matched**: the full chain, e.g. `include:_spf.google.com -> include:_netblocks.google.com -> ip4:35.190.0.0/17`.
3. **The errors hit along the way**, e.g. exceeding the 10 DNS-lookup limit.

Unlike a strict implementation, evaluation keeps going past the RFC processing limits, so you get both
the RFC-strict `Result` and the `EffectiveResult` that would apply if the record were fixed.

```go
import "github.com/VenditoKft/spfer"

res := spfer.Check(ctx, netip.MustParseAddr("192.0.2.1"), "example.com")
// or, with sender and HELO for macro expansion:
res = spfer.CheckHost(ctx, ip, "example.com", "alice@example.com", "mx.example.org")

res.Result          // RFC-strict result
res.EffectiveResult // result ignoring soft limits
res.Match.Top()     // directive of example.com's own record that matched
res.Match.Leaf()    // mechanism that matched the IP
res.Errors          // []*spfer.Error; use errors.Is(err, spfer.ErrLookupLimit) etc.
res.Lookups         // RFC-counted DNS lookups (may exceed 10)
```

`Match` is nil when no mechanism matched (default neutral, none) or when evaluation ended in an error.

## Limits

| Limit | Default | Kind | On breach |
|---|---|---|---|
| DNS-mechanism lookups (`include a mx ptr exists redirect`) | 10 | soft | `ErrLookupLimit`, `Result=permerror`, evaluation continues |
| Void lookups (NXDOMAIN / no data) | 2 | soft | `ErrVoidLimit`, same as above |
| MX names per `mx` | 10 | soft | `ErrMXLimit`, same as above |
| PTR names per `ptr` | 10 | RFC | extra names are ignored (`ErrPTRLimit`, informational only, as RFC 7208 §4.6.4 specifies) |
| Lookups per top-level subtree | 25 | hard | `ErrSubtreeBudget`, `Result=permerror`; for `EffectiveResult` that top-level term counts as not matching and evaluation moves on |

Each top-level `include` and `redirect` gets its own 25-lookup budget covering everything nested beneath it.
Top-level `a`/`mx`/`ptr`/`exists` share a separate root budget. The A/AAAA lookups for MX and PTR names also
draw from the budget (but not from the RFC counter). Include/redirect loops are detected directly (`ErrLoop`).

Rule: `Result` is `permerror` whenever any soft limit was breached; otherwise it equals `EffectiveResult`.
Temperror and other permerrors (syntax, loop, missing or multiple records) apply to both.

## Options

`WithResolver`, `WithExplanation` (fetch `exp=` on fail; this lookup is not counted), `WithLookupLimit`,
`WithVoidLimit`, `WithSubtreeBudget`, `WithQueryTimeout`, `WithReceivingHost` (`%{r}`).

DNS goes through the `Resolver` interface. The default uses `net.DefaultResolver`, and `NetResolver` wraps
any other `*net.Resolver`. A custom resolver must return `ErrNotFound` (wrapping is fine) for NXDOMAIN or
no data; any other error is treated as a temporary failure. Queries are cached within one evaluation, and
cache hits still count toward the limits.

## Testing

```
go test -race ./...
```

Includes the OpenSPF RFC 7208 test suite (`testdata/rfc7208-tests.yml`), checked against the strict `Result`.
