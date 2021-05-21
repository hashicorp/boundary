package event

import "github.com/hashicorp/boundary/internal/errors"

// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type Observation struct {
	Details     map[string]interface{} `json:"details,omitempty"`
	Header      map[string]interface{} `json:"header,omitempty"`
	Id          Id                     `json:"id,omitempty"`
	Op          Op                     `json:"op,omitempty"`
	RequestInfo *RequestInfo           `json:"request_info,omitempty"`
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
		Id:          Id(opts.withId),
		Op:          fromOperation,
		RequestInfo: opts.withRequestInfo,
		Header:      opts.withHeader,
		Details:     opts.withDetails,
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
	if i.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing event id")
	}
	if i.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation which raised event")
	}
	return nil
}
