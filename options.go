package spfer

import "time"

const (
	defaultLookupLimit   = 10
	defaultVoidLimit     = 2
	defaultMXLimit       = 10
	defaultPTRLimit      = 10
	defaultSubtreeBudget = 25
)

// Option configures an evaluation.
type Option func(*options)

type options struct {
	resolver      Resolver
	explanation   bool
	lookupLimit   int
	voidLimit     int
	subtreeBudget int
	queryTimeout  time.Duration
	receivingHost string
	now           func() time.Time
}

func newOptions(opts []Option) *options {
	o := &options{
		lookupLimit:   defaultLookupLimit,
		voidLimit:     defaultVoidLimit,
		subtreeBudget: defaultSubtreeBudget,
		receivingHost: "unknown",
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(o)
	}
	if o.resolver == nil {
		o.resolver = DefaultResolver()
	}
	return o
}

// WithResolver sets the DNS resolver. The default is DefaultResolver().
func WithResolver(r Resolver) Option { return func(o *options) { o.resolver = r } }

// WithExplanation fetches and expands the exp= explanation when the effective
// result is fail. The extra lookup does not count toward any limit.
func WithExplanation() Option { return func(o *options) { o.explanation = true } }

// WithLookupLimit sets the soft DNS-mechanism lookup limit (default 10).
func WithLookupLimit(n int) Option { return func(o *options) { o.lookupLimit = n } }

// WithVoidLimit sets the soft void lookup limit (default 2).
func WithVoidLimit(n int) Option { return func(o *options) { o.voidLimit = n } }

// WithSubtreeBudget sets the hard lookup budget of each top-level subtree
// (default 25).
func WithSubtreeBudget(n int) Option { return func(o *options) { o.subtreeBudget = n } }

// WithQueryTimeout bounds each individual DNS query, in addition to the
// context passed to Check.
func WithQueryTimeout(d time.Duration) Option { return func(o *options) { o.queryTimeout = d } }

// WithReceivingHost sets the value of the %{r} macro (default "unknown").
func WithReceivingHost(name string) Option { return func(o *options) { o.receivingHost = name } }
