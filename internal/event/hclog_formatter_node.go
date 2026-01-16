// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/fatih/structs"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

const (
	infoField        = "Info"
	errorFields      = "ErrorFields"
	requestInfoField = "RequestInfo"
	wrappedField     = "Wrapped"
	hclogNodeName    = "hclog-formatter-filter"
)

// hclogFormatterFilter will format a boundary event an an hclog entry.
type hclogFormatterFilter struct {
	// jsonFormat allows you to specify that the hclog entry should be in JSON
	// fmt.
	jsonFormat bool
	predicate  func(ctx context.Context, i any) (bool, error)
	allow      []*filter
	deny       []*filter
	signer     signer
	// l protects the signer field
	l sync.RWMutex
}

func newHclogFormatterFilter(jsonFormat bool, opt ...Option) (*hclogFormatterFilter, error) {
	const op = "event.newHclogFormatterFilter"
	opts := getOpts(opt...)
	var s signer
	n := hclogFormatterFilter{
		jsonFormat: jsonFormat,
		signer:     s,
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
	defaultDenyFilters, err := defaultHclogEventsDenyFilters()
	if err != nil {
		return nil, err
	}
	n.deny = append(n.deny, defaultDenyFilters...)
	n.predicate = newPredicate(n.allow, n.deny)

	return &n, nil
}

func defaultHclogEventsDenyFilters() ([]*filter, error) {
	const (
		op = "event.defaultHclogEventsDenyFilters"
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
func (f *hclogFormatterFilter) Rotate(w wrapping.Wrapper, _ ...Option) error {
	const op = "event.(hclogFormatterFilter).Rotate"
	if w == nil {
		return fmt.Errorf("%s: missing wrapper: %w", op, ErrInvalidParameter)
	}
	f.l.Lock()
	defer f.l.Unlock()
	h, err := newSigner(context.Background(), w, nil, nil)
	if err != nil {
		return err
	}
	f.signer = h
	return nil
}

// Reopen is a no op
func (*hclogFormatterFilter) Reopen() error { return nil }

// Type describes the type of the node as a Formatter.
func (*hclogFormatterFilter) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeFormatterFilter
}

// Name returns a representation of the HclogFormatter's name
func (*hclogFormatterFilter) Name() string {
	return hclogNodeName
}

// Process formats the Boundary event as an hclog entry and stores that
// formatted data in Event.Formatted with a key of either "hclog-text"
// (TextHclogSinkFormat) or "hclog-json" (JSONHclogSinkFormat) based on the
// HclogFormatter.JSONFormat value.
//
// If the node has a Predicate, then the filter will be applied to event.Payload
func (f *hclogFormatterFilter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(HclogFormatter).Process"
	if e == nil {
		return nil, errors.New("event is nil")
	}

	if f.predicate != nil {
		// Use the predicate to see if we want to keep the event using it's
		// formatted struct as a parmeter to the predicate.
		keep, err := f.predicate(ctx, e.Payload)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to filter: %w", op, err)
		}
		if !keep {
			// Return nil to signal that the event should be discarded.
			return nil, nil
		}
	}

	var m map[string]any
	switch string(e.Type) {
	case string(ErrorType), string(AuditType), string(SystemType):
		s := structs.New(e.Payload)
		s.TagName = "json"
		m = s.Map()
	case string(ObservationType):
		m = e.Payload.(map[string]any)
	default:
		return nil, fmt.Errorf("%s: unknown event type %s", op, e.Type)
	}

	args := make([]any, 0, len(m))
	for k, v := range m {
		if k == requestInfoField && v == nil {
			continue
		}
		if !f.jsonFormat && v != nil {
			var underlyingPtr bool
			valueKind := reflect.TypeOf(v).Kind()
			if valueKind == reflect.Ptr {
				underlyingPtr = true
				valueKind = reflect.TypeOf(v).Elem().Kind()
			}
			switch {
			case valueKind == reflect.Map:
				for sk, sv := range v.(map[string]any) {
					args = append(args, k+":"+sk, sv)
				}
				continue
			case valueKind == reflect.Struct:
				if underlyingPtr && (v == nil || reflect.ValueOf(v).IsNil()) {
					continue
				}
				for sk, sv := range structs.Map(v) {
					args = append(args, k+":"+sk, sv)
				}
				continue
			}
		}
		switch string(e.Type) {
		case string(ErrorType):
			switch {
			case k == errorFields && v == nil:
				continue
			case k == infoField && len(v.(map[string]any)) == 0:
				continue
			case k == wrappedField && v == nil:
				continue
			}
		}
		args = append(args, k, v)
	}

	buf, err := hclogBytes(e.Type, f.jsonFormat, args)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to format: %w", op, err)
	}
	f.l.Lock()
	defer f.l.Unlock()
	if f.signer != nil && string(e.Type) == string(AuditType) {
		bufHmac, err := f.signer(ctx, buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s: unable to hmac-sha256: %w", op, err)
		}
		args = append(args, "serialized", base64.RawURLEncoding.EncodeToString(buf.Bytes()), "serialized_hmac", bufHmac)
		buf, err = hclogBytes(e.Type, f.jsonFormat, args)
		if err != nil {
			return nil, fmt.Errorf("%s: unable to format after hmac-sha256: %w", op, err)
		}
	}
	switch f.jsonFormat {
	case true:
		e.FormattedAs(string(JSONHclogSinkFormat), buf.Bytes())
	case false:
		e.FormattedAs(string(TextHclogSinkFormat), buf.Bytes())
	}

	return e, nil
}

func hclogBytes(eventType eventlogger.EventType, jsonFormat bool, args []any) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	logger := hclog.New(&hclog.LoggerOptions{
		Output:     &buf,
		Level:      hclog.Trace,
		JSONFormat: jsonFormat,
	})
	const eventMarker = " event"
	switch string(eventType) {
	case string(ErrorType):
		logger.Error(string(eventType)+eventMarker, args...)
	case string(ObservationType), string(SystemType), string(AuditType):
		logger.Info(string(eventType)+eventMarker, args...)
	default:
		// well, we should ever hit this, since we should be specific about the
		// event type we're processing, but adding this default to just be sure
		// we haven't missed anything.
		logger.Trace(string(eventType)+eventMarker, args...)
	}
	return &buf, nil
}
