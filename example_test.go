package spfer_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/VenditoKft/spfer"
)

func ExampleCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res := spfer.Check(ctx, netip.MustParseAddr("192.0.2.1"), "example.com",
		spfer.WithQueryTimeout(2*time.Second))

	fmt.Println("strict:", res.Result, "effective:", res.EffectiveResult)
	if res.Match != nil {
		fmt.Println("matched via:", res.Match.Top().Term, "leaf:", res.Match.Leaf().Term)
	}
	for _, err := range res.Errors {
		if errors.Is(err, spfer.ErrLookupLimit) {
			fmt.Println("record exceeds the 10 lookup limit")
		}
	}
}

func ExampleCheckAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res := spfer.CheckAll(ctx, netip.MustParseAddr("192.0.2.1"), "example.com")
	fmt.Println("result:", res.Result)
	for _, m := range res.Matches {
		fmt.Println("matches via:", m)
	}
}
