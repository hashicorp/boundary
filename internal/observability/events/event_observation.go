package event

import (
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
)

// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type Observation struct {
	eventlogger.SimpleGatedPayload
	Op          Op           `json:"op,omitempty"`
	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}

func NewObservation(fromOperation Op, opt ...Option) (*Observation, error) {
	const op = "event.NewObservation"
	if fromOperation == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing from operation")
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = newId(string(ObservationType))
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
	}
	i := &Observation{
		SimpleGatedPayload: eventlogger.SimpleGatedPayload{
			ID:     opts.withId,
			Header: opts.withHeader,
			Detail: opts.withDetails,
		},
		Op:          fromOperation,
		RequestInfo: opts.withRequestInfo,
	}
	if err := i.validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return i, nil
}

// EventType is required for all event types by the eventlogger broker
func (i *Observation) EventType() string { return string(ObservationType) }

func (i *Observation) validate() error {
	const op = "event.(Observation).validate"
	if i.ID == "" {
		return errors.New(errors.InvalidParameter, op, "missing event id")
	}
	if i.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation which raised event")
	}
	return nil
}
