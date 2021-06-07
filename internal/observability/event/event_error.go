package event

import "github.com/hashicorp/boundary/internal/errors"

// errorVersion defines the version of error events
const errorVersion = "v0.1"

type err struct {
	Error       error        `json:"error"`
	Id          Id           `json:"id,omitempty"`
	Version     string       `json:"version"`
	Op          Op           `json:"op,omitempty"`
	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}

func newError(fromOperation Op, e error, opt ...Option) (*err, error) {
	const op = "event.newError"
	if fromOperation == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing operation")
	}
	if e == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing error")
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = newId(string(ErrorType))
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
	}
	newErr := &err{
		Id:          Id(opts.withId),
		Op:          fromOperation,
		Version:     errorVersion,
		RequestInfo: opts.withRequestInfo,
		Error:       e,
	}
	if err := newErr.validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return newErr, nil
}

// EventType is required for all event types by the eventlogger broker
func (e *err) EventType() string { return string(ErrorType) }

func (e *err) validate() error {
	const op = "event.(err).validate"
	if e.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing id")
	}
	if e.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation")
	}
	if e.Error == nil {
		return errors.New(errors.InvalidParameter, op, "missing error")
	}
	return nil
}
