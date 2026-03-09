// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/filter"
	"github.com/hashicorp/go-bexpr"
)

// filterItem captures all the different namespaces that can be used when
// filtering an item.
type filterItem struct {
	Item any `json:"item"`
}

type Filter struct {
	eval *bexpr.Evaluator
}

// NewFilter returns a Filter which can be evaluated against.  An empty string parameter indicates
// all items passed to it should succeed.
func NewFilter(ctx context.Context, f string) (*Filter, error) {
	const op = "handlers.NewFilter"
	if f == "" {
		return &Filter{}, nil
	}
	e, err := bexpr.CreateEvaluator(f, bexpr.WithTagName("json"), bexpr.WithHookFn(filter.WellKnownTypeFilterHook))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("couldn't build filter"), errors.WithCode(errors.InvalidParameter))
	}
	return &Filter{eval: e}, nil
}

// Match returns if the provided interface matches the filter.
// If the filter does not match the structure of the object being Matched, false is returned.
// TODO: Support more than just matching against the item being filtered.  Also allow matching against
// values in the request or the request context itself.
func (f *Filter) Match(item any) bool {
	if f.eval == nil {
		return true
	}
	m, err := f.eval.Evaluate(filterItem{Item: item})
	// There isn't a clear way to differentiate between a JSON Pointer which doesn't represent
	// the structure of the object being Matched and a JSON Pointer which references a field which
	// is part of a sub structure that is nil in this item. Because of this, any filter which would
	// result in an error using the underlying library is simply interpreted as not a match.
	return err == nil && m
}
