package filter

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hashicorp/boundary/internal/observability/event"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Node represents an eventlogger.Node which filters events based on allow and
// deny bexpr filters
type Node struct {
	allow []*filter
	deny  []*filter
}

// NewNode creates a new filter node using the optional allow and deny filters
// provided.
func NewNode(opt ...Option) (*Node, error) {
	const op = "filter.NewNode"
	opts := getOpts(opt...)
	// intentionally not checking of allow and/or deny optional filters were
	// supplied since having a filter node with no filters is okay.
	n := Node{}
	if len(opts.withAllow) > 0 {
		n.allow = make([]*filter, 0, len((opts.withAllow)))
		for i := range opts.withAllow {
			f, err := newFilter(opts.withAllow[i])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid allow filter %s: %w", op, opts.withAllow[i], err)
			}
			n.allow = append(n.allow, f)
		}
	}
	if len(opts.withDeny) > 0 {
		n.allow = make([]*filter, 0, len((opts.withDeny)))
		for i := range opts.withDeny {
			f, err := newFilter(opts.withDeny[i])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid deny filter %s: %w", op, opts.withDeny[i], err)
			}
			n.deny = append(n.deny, f)
		}
	}
	return &n, nil
}

var _ eventlogger.Node = &Node{}

// Process will filter the event based on the node's allow and deny filters.
// Deny filters are applied first and if any match the event is excluded (nil,
// nil is returned).  The allow filters are applied after the denies and if any
// match the event is included (event, nil is returned).   Both allow and deny
// filters are optional.
func (n *Node) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	if len(n.allow) == 0 && len(n.deny) == 0 {
		return e, nil
	}
	for _, f := range n.deny {
		if f.Match(e) {
			return nil, nil
		}
	}
	switch {
	case len(n.allow) > 0:
		for _, f := range n.allow {
			if f.Match(e) {
				return e, nil
			}
		}
		return nil, nil
	default:
		return e, nil
	}
}

// Reopen is a no op for Filters.
func (_ *Node) Reopen() error {
	return nil
}

// Type describes the type of the node as a Filter.
func (_ *Node) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeFilter
}

type filter struct {
	eval *bexpr.Evaluator
}

// newFilter returns a Filter which can be matched against.
func newFilter(f string) (*filter, error) {
	const op = "filter.NewFilter"
	if f == "" {
		return nil, fmt.Errorf("%s: missing filter: %w", op, event.ErrInvalidParameter)
	}
	e, err := bexpr.CreateEvaluator(f, bexpr.WithHookFn(wellKnownTypeFilterHook))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &filter{eval: e}, nil
}

// Match returns if the provided interface matches the filter. If the filter
// does not match the structure of the object being Matched, false is returned.
func (f *filter) Match(item interface{}) bool {
	if f.eval == nil {
		return true
	}
	m, err := f.eval.Evaluate(item)
	// There isn't a clear way to differentiate between a JSON Pointer which doesn't represent
	// the structure of the object being Matched and a JSON Pointer which references a field which
	// is part of a sub structure that is nil in this item. Because of this, any filter which would
	// result in an error using the underlying library is simply interpreted as not a match.
	return err == nil && m
}

// wellKnownTypeFilterHook is passed to bexpr to treat all proto well-known
// types as the types they wrap for comparison.
func wellKnownTypeFilterHook(v reflect.Value) reflect.Value {
	if !v.CanInterface() {
		return v
	}
	ret := v.Interface()
	switch pm := v.Interface().(type) {
	case *wrapperspb.BoolValue:
		ret = pm.GetValue()
	case *wrapperspb.BytesValue:
		ret = pm.GetValue()
	case *wrapperspb.StringValue:
		ret = pm.GetValue()
	case *wrapperspb.DoubleValue:
		ret = pm.GetValue()
	case *wrapperspb.FloatValue:
		ret = pm.GetValue()
	case *wrapperspb.Int32Value:
		ret = pm.GetValue()
	case *wrapperspb.Int64Value:
		ret = pm.GetValue()
	case *wrapperspb.UInt32Value:
		ret = pm.GetValue()
	case *wrapperspb.UInt64Value:
		ret = pm.GetValue()
	case *structpb.Struct:
		ret = pm.AsMap()
	case *timestamppb.Timestamp:
		ret = pm.AsTime()
	}
	return reflect.ValueOf(ret)
}
