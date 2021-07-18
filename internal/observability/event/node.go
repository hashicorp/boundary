package event

import (
	"context"
	"fmt"
	"net/url"
	"reflect"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-bexpr"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Node represents an eventlogger.Node which filters events based on allow and
// deny bexpr filters
type Node struct {
	*cloudevents.FormatterFilter
	allow []*filter
	deny  []*filter
}

// NewCloudEventsNode creates a new filter node using the optional allow and deny filters
// provided. Support for WithAllow and WithDeny options.
func NewCloudEventsNode(source *url.URL, format cloudevents.Format, opt ...Option) (*Node, error) {
	const op = "filter.NewNode"
	if source == nil {
		return nil, fmt.Errorf("%s: missing source: %w", op, ErrInvalidParameter)
	}
	switch format {
	case cloudevents.FormatJSON, cloudevents.FormatText:
	default:
		return nil, fmt.Errorf("%s: invalid format '%s': %w", op, format, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	n := Node{
		FormatterFilter: &cloudevents.FormatterFilter{
			Source: source,
			Schema: opts.withSchema,
			Format: format,
		},
	}

	// intentionally not checking of allow and/or deny optional filters were
	// supplied since having a filter node with no filters is okay.

	if len(opts.withAllow) > 0 {
		n.allow = make([]*filter, 0, len((opts.withAllow)))
		for i := range opts.withAllow {
			f, err := newFilter(opts.withAllow[i])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid allow filter '%s': %w", op, opts.withAllow[i], err)
			}
			n.allow = append(n.allow, f)
		}
	}
	if len(opts.withDeny) > 0 {
		n.deny = make([]*filter, 0, len((opts.withDeny)))
		for i := range opts.withDeny {
			f, err := newFilter(opts.withDeny[i])
			if err != nil {
				return nil, fmt.Errorf("%s: invalid deny filter '%s': %w", op, opts.withDeny[i], err)
			}
			n.deny = append(n.deny, f)
		}
	}
	n.Predicate = newPredicate(n.allow, n.deny)
	return &n, nil
}

func newPredicate(allow, deny []*filter) func(ctx context.Context, ce interface{}) (bool, error) {
	return func(ctx context.Context, ce interface{}) (bool, error) {
		if len(allow) == 0 && len(deny) == 0 {
			return true, nil
		}
		for _, f := range deny {
			if f.Match(ce) {
				return false, nil
			}
		}
		switch {
		case len(allow) > 0:
			for _, f := range allow {
				if f.Match(ce) {
					return true, nil
				}
			}
			return false, nil
		default:
			return true, nil
		}
	}
}

var _ eventlogger.Node = &Node{}

type filter struct {
	raw  string
	eval *bexpr.Evaluator
}

// newFilter returns a Filter which can be matched against.
func newFilter(f string) (*filter, error) {
	const op = "filter.NewFilter"
	if f == "" {
		return nil, fmt.Errorf("%s: missing filter: %w", op, ErrInvalidParameter)
	}
	e, err := bexpr.CreateEvaluator(f, bexpr.WithHookFn(wellKnownTypeFilterHook))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &filter{eval: e, raw: f}, nil
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
