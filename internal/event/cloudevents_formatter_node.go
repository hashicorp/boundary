// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	filterpkg "github.com/hashicorp/boundary/internal/filter"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-bexpr"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// cloudEventsFormatterFilter represents an eventlogger.cloudEventsFormatterFilter which filters events based on allow and
// deny bexpr filters
type cloudEventsFormatterFilter struct {
	*cloudevents.FormatterFilter
	allow []*filter
	deny  []*filter
	l     sync.RWMutex
}

// newCloudEventsFormatterFilter creates a new filter node using the optional allow and deny filters
// provided. Support for WithAllow and WithDeny options.
func newCloudEventsFormatterFilter(source *url.URL, format cloudevents.Format, opt ...Option) (*cloudEventsFormatterFilter, error) {
	const op = "event.NewCloudEventsNode"
	if source == nil {
		return nil, fmt.Errorf("%s: missing source: %w", op, ErrInvalidParameter)
	}
	switch format {
	case cloudevents.FormatJSON, cloudevents.FormatText:
	default:
		return nil, fmt.Errorf("%s: invalid format '%s': %w", op, format, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	n := cloudEventsFormatterFilter{
		FormatterFilter: &cloudevents.FormatterFilter{
			Source:         source,
			Schema:         opts.withSchema,
			Format:         format,
			SignEventTypes: []string{string(AuditType)},
		},
	}

	// intentionally not checking if allow and/or deny optional filters were
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
	// if the user does not specify any filter (allow/deny), we add default deny filter
	if len(opts.withDeny) == 0 && len(opts.withAllow) == 0 {
		defaultDenyFilters, err := defaultCloudEventsDenyFilters()
		if err != nil {
			return nil, err
		}
		n.deny = append(n.deny, defaultDenyFilters...)
	}

	n.Predicate = newPredicate(n.allow, n.deny)
	return &n, nil
}

func defaultCloudEventsDenyFilters() ([]*filter, error) {
	const (
		op = "event.defaultCloudEventsDenyFilters"
		// denyWorkStatusEvents is a default filter for worker to controller API status requests
		denyWorkStatusEvents      = `"/type" contains "observation" and "/data/request_info/method" contains "ServerCoordinationService/Status"`
		denyWorkSessionInfoEvents = `"/type" contains "observation" and "/data/request_info/method" contains "ServerCoordinationService/SessionInfo"`
		denyWorkRoutingInfoEvents = `"/type" contains "observation" and "/data/request_info/method" contains "ServerCoordinationService/RoutingInfo"`
		denyWorkStatisticsEvents  = `"/type" contains "observation" and "/data/request_info/method" contains "ServerCoordinationService/Statistics"`
	)
	statusFilter, err := newFilter(denyWorkStatusEvents)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create deny filter for worker status events '%s': %w", op, denyWorkStatusEvents, err)
	}
	sessionInfoFilter, err := newFilter(denyWorkSessionInfoEvents)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create deny filter for worker session info events '%s': %w", op, denyWorkStatusEvents, err)
	}
	routingInfoFilter, err := newFilter(denyWorkRoutingInfoEvents)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create deny filter for worker routing info events '%s': %w", op, denyWorkStatusEvents, err)
	}
	statisticsFilter, err := newFilter(denyWorkStatisticsEvents)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create deny filter for worker statistics events '%s': %w", op, denyWorkStatusEvents, err)
	}
	return []*filter{statusFilter, sessionInfoFilter, routingInfoFilter, statisticsFilter}, nil
}

// Rotate supports rotating the filter's wrapper. No options are currently
// supported.
func (f *cloudEventsFormatterFilter) Rotate(w wrapping.Wrapper, _ ...Option) error {
	const op = "event.(cloudEventsFormatterFilter).Rotate"
	if w == nil {
		return fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	f.l.Lock()
	defer f.l.Unlock()
	h, err := newSigner(context.Background(), w, nil, nil)
	if err != nil {
		return err
	}
	f.Signer = cloudevents.Signer(h)
	return nil
}

func (f *cloudEventsFormatterFilter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	// The embedded FormatterFilter's Process function calls the signer, but doesn't know
	// about the lock, leading to a potential race condition. We take the lock here to ensure
	// that the signer is only accessed by one goroutine at a time.
	f.l.RLock()
	defer f.l.RUnlock()
	return f.FormatterFilter.Process(ctx, e)
}

func newPredicate(allow, deny []*filter) func(ctx context.Context, ce any) (bool, error) {
	return func(ctx context.Context, ce any) (bool, error) {
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

var _ eventlogger.Node = &cloudEventsFormatterFilter{}

type filter struct {
	raw  string
	eval *bexpr.Evaluator
}

// newFilter returns a Filter which can be matched against.
func newFilter(f string) (*filter, error) {
	const op = "event.newFilter"
	if f == "" {
		return nil, fmt.Errorf("%s: missing filter: %w", op, ErrInvalidParameter)
	}
	// explicitly tell the filter to use the "json" tags so we don't have to
	// re-tag everything with a mapstructure tag via bexpr.WithTagName("json")
	e, err := bexpr.CreateEvaluator(f, bexpr.WithHookFn(filterpkg.WellKnownTypeFilterHook), bexpr.WithTagName("json"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &filter{eval: e, raw: f}, nil
}

// Match returns if the provided interface matches the filter. If the filter
// does not match the structure of the object being Matched, false is returned.
func (f *filter) Match(item any) bool {
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
