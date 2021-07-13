package event

import (
	"fmt"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/shared-secure-libs/strutil"
)

// observationVersion defines the version of observation events
const observationVersion = "v0.1"

type observation struct {
	*eventlogger.SimpleGatedPayload
	Version     string       `json:"version"`
	Op          Op           `json:"op,omitempty"`
	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}

func newObservation(fromOperation Op, opt ...Option) (*observation, error) {
	const op = "event.newObservation"
	if fromOperation == "" {
		return nil, fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = newId(string(ObservationType))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	for k := range opts.withHeader {
		if strutil.StrListContains([]string{OpField, VersionField, RequestInfoField}, k) {
			return nil, fmt.Errorf("%s: %s is a reserved field name: %w", op, k, ErrInvalidParameter)
		}
	}
	i := &observation{
		SimpleGatedPayload: &eventlogger.SimpleGatedPayload{
			ID:     opts.withId,
			Header: opts.withHeader,
			Detail: opts.withDetails,
			Flush:  opts.withFlush,
		},
		Op:          fromOperation,
		RequestInfo: opts.withRequestInfo,
		Version:     observationVersion,
	}
	if err := i.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return i, nil
}

// EventType is required for all event types by the eventlogger broker
func (i *observation) EventType() string { return string(ObservationType) }

func (i *observation) validate() error {
	const op = "event.(Observation).validate"
	if i.ID == "" {
		return fmt.Errorf("%s: missing id: %w", op, ErrInvalidParameter)
	}
	if i.Op == "" {
		return fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	return nil
}
