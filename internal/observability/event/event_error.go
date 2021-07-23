package event

import (
	"fmt"
)

// errorVersion defines the version of error events
const errorVersion = "v0.1"

type err struct {
	Error       error                  `json:"error"`
	Id          Id                     `json:"id,omitempty"`
	Version     string                 `json:"version"`
	Op          Op                     `json:"op,omitempty"`
	RequestInfo *RequestInfo           `json:"request_info,omitempty"`
	Info        map[string]interface{} `json:"info,omitempty"`
}

func newError(fromOperation Op, e error, opt ...Option) (*err, error) {
	const op = "event.newError"
	if fromOperation == "" {
		return nil, fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	if e == nil {
		return nil, fmt.Errorf("%s: missing error: %w", op, ErrInvalidParameter)
	}
	opts := getOpts(opt...)
	if opts.withId == "" {
		var err error
		opts.withId, err = newId(string(ErrorType))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	if opts.withInfoMsg != "" {
		if opts.withInfo == nil {
			opts.withInfo = map[string]interface{}{
				"msg": opts.withInfoMsg,
			}
		} else {
			opts.withInfo["msg"] = opts.withInfoMsg
		}
	}
	newErr := &err{
		Id:          Id(opts.withId),
		Op:          fromOperation,
		Version:     errorVersion,
		RequestInfo: opts.withRequestInfo,
		Info:        opts.withInfo,
		Error:       e,
	}
	if err := newErr.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return newErr, nil
}

// EventType is required for all event types by the eventlogger broker
func (e *err) EventType() string { return string(ErrorType) }

func (e *err) validate() error {
	const op = "event.(err).validate"
	if e.Id == "" {
		return fmt.Errorf("%s: missing id: %w", op, ErrInvalidParameter)
	}
	if e.Op == "" {
		return fmt.Errorf("%s: missing operation: %w", op, ErrInvalidParameter)
	}
	if e.Error == nil {
		return fmt.Errorf("%s: missing error: %w", op, ErrInvalidParameter)
	}
	return nil
}
