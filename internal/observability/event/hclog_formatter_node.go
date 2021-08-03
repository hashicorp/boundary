package event

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/fatih/structs"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
)

const (
	infoField        = "Info"
	errorFields      = "ErrorFields"
	requestInfoField = "RequestInfo"
	hclogNodeName    = "hclog-formatter-filter"
)

// hclogFormatterFilter will format a boundary event an an hclog entry.
type hclogFormatterFilter struct {
	// jsonFormat allows you to specify that the hclog entry should be in JSON
	// fmt.
	jsonFormat bool
	predicate  func(ctx context.Context, i interface{}) (bool, error)
	allow      []*filter
	deny       []*filter
}

func newHclogFormatterFilter(jsonFormat bool, opt ...Option) (*hclogFormatterFilter, error) {
	const op = "event.NewHclogFormatter"
	n := hclogFormatterFilter{
		jsonFormat: jsonFormat,
	}
	opts := getOpts(opt...)
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
	n.predicate = newPredicate(n.allow, n.deny)

	return &n, nil

}

// Reopen is a no op
func (_ *hclogFormatterFilter) Reopen() error { return nil }

// Type describes the type of the node as a Formatter.
func (_ *hclogFormatterFilter) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeFormatterFilter
}

// Name returns a representation of the HclogFormatter's name
func (_ *hclogFormatterFilter) Name() string {
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

	var m map[string]interface{}
	switch string(e.Type) {
	case string(ErrorType), string(AuditType), string(SystemType):
		m = structs.Map(e.Payload)
	case string(ObservationType):
		m = e.Payload.(map[string]interface{})
	default:
		return nil, fmt.Errorf("%s: unknown event type %s", op, e.Type)
	}

	args := make([]interface{}, 0, len(m))
	for k, v := range m {
		if k == requestInfoField && v == nil {
			continue
		}
		switch string(e.Type) {
		case string(ErrorType):
			if k == errorFields && v == nil {
				continue
			}
			if k == infoField && len(v.(map[string]interface{})) == 0 {
				continue
			}
		}
		args = append(args, k, v)
	}

	var buf bytes.Buffer
	logger := hclog.New(&hclog.LoggerOptions{
		Output:     &buf,
		Level:      hclog.Trace,
		JSONFormat: f.jsonFormat,
	})
	const eventMarker = " event"
	switch string(e.Type) {
	case string(ErrorType):
		logger.Error(string(e.Type)+eventMarker, args...)
	case string(ObservationType), string(SystemType), string(AuditType):
		logger.Info(string(e.Type)+eventMarker, args...)
	default:
		logger.Trace(string(e.Type)+eventMarker, args...)
	}
	switch f.jsonFormat {
	case true:
		e.FormattedAs(string(JSONHclogSinkFormat), buf.Bytes())
	case false:
		e.FormattedAs(string(TextHclogSinkFormat), buf.Bytes())
	}

	return e, nil
}
