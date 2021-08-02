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
)

// HclogFormatter will format a boundary event an an hclog entry.
type HclogFormatter struct {
	// JSONFormat allows you to specify that the hclog entry should be in JSON
	// fmt.
	JSONFormat bool
}

// Reopen is a no op
func (_ *HclogFormatter) Reopen() error { return nil }

// Type describes the type of the node as a Formatter.
func (_ *HclogFormatter) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeFormatter
}

// Name returns a representation of the HclogFormatter's name
func (_ *HclogFormatter) Name() string {
	const name = "hclog-formatter"
	return name
}

// Process formats the Boundary event as an hclog entry and stores that
// formatted data in Event.Formatted with a key of either "hclog-text"
// (TextHclogSinkFormat) or "hclog-json" (JSONHclogSinkFormat) based on the
// HclogFormatter.JSONFormat value.
func (f *HclogFormatter) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	const op = "event.(HclogFormatter).Process"
	if e == nil {
		return nil, errors.New("event is nil")
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
		JSONFormat: f.JSONFormat,
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
	switch f.JSONFormat {
	case true:
		e.FormattedAs(string(JSONHclogSinkFormat), buf.Bytes())
	case false:
		e.FormattedAs(string(TextHclogSinkFormat), buf.Bytes())
	}

	return e, nil
}
