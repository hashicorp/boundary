package event

import (
	"github.com/hashicorp/boundary/internal/errors"
)

type Type string

const (
	EveryType Type = "*"
	InfoType  Type = "info"
	AuditType Type = "audit"
	ErrorType Type = "error"
)

type Id string
type Op string

// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type Audit struct {
	Id          Id           `json:"id,omitempty"`
	Op          Op           `json:"op,omitempty"`
	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}

// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type Err struct {
	e           error
	Id          Id           `json:"id,omitempty"`
	Op          Op           `json:"op,omitempty"`
	RequestInfo *RequestInfo `json:"request_info,omitempty"`
}

func NewError(fromOperation Op, e error, opt ...Option) (*Err, error) {
	const op = "event.NewError"
	if fromOperation == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing from operation")
	}
	id, err := newId(string(InfoType))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	opts := getOpts(opt...)
	newErr := &Err{
		Id:          Id(id),
		Op:          fromOperation,
		RequestInfo: opts.withRequestInfo,
		e:           e,
	}
	if err := newErr.validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}
	return newErr, nil
}

func (e *Err) validate() error {
	const op = "event.(Info).validate"
	if e.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing event id")
	}
	if e.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation which raised event")
	}
	return nil
}

// fields are intentionally alphabetically ordered so they will match output
// from marshaling event json
type Info struct {
	Details     map[string]interface{} `json:"details,omitempty"`
	Header      map[string]interface{} `json:"header,omitempty"`
	Id          Id                     `json:"id,omitempty"`
	Op          Op                     `json:"op,omitempty"`
	RequestInfo *RequestInfo           `json:"request_info,omitempty"`
}

func NewInfo(fromOperation Op, opt ...Option) (*Info, error) {
	const op = "event.NewInfo"
	opts := getOpts(opt...)
	if fromOperation == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing from operation")
	}
	id, err := newId(string(InfoType))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	i := &Info{
		Id:          Id(id),
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

func (i *Info) EventType() string { return string(InfoType) }

func (i *Info) validate() error {
	const op = "event.(Info).validate"
	if i.Id == "" {
		return errors.New(errors.InvalidParameter, op, "missing event id")
	}
	if i.Op == "" {
		return errors.New(errors.InvalidParameter, op, "missing operation which raised event")
	}
	return nil
}
