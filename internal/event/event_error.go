// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package event

import (
	"errors"
	"fmt"
	"reflect"
)

// errorVersion defines the version of error events
const errorVersion = "v0.1"

type err struct {
	Error       string         `json:"error"`
	ErrorFields error          `json:"error_fields"`
	Id          Id             `json:"id,omitempty"`
	Version     string         `json:"version"`
	Op          Op             `json:"op,omitempty"`
	RequestInfo *RequestInfo   `json:"request_info,omitempty"`
	Info        map[string]any `json:"info,omitempty"`
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
		opts.withId, err = NewId(string(ErrorType))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}
	// multierror doesn't support json Marshaling which will cause a problem
	// when the event is formatted, so we're going to convert it here to a
	// stdlib error
	if reflect.TypeOf(e).String() == "*multierror.Error" {
		e = errors.New(e.Error())
	}
	newErr := &err{
		Id:          Id(opts.withId),
		Op:          fromOperation,
		Version:     errorVersion,
		RequestInfo: opts.withRequestInfo,
		Info:        opts.withInfo,
		Error:       e.Error(),
		ErrorFields: e,
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
	if e.ErrorFields == nil {
		return fmt.Errorf("%s: missing error fields: %w", op, ErrInvalidParameter)
	}
	if e.Error == "" {
		return fmt.Errorf("%s: missing error: %w", op, ErrInvalidParameter)
	}
	return nil
}
