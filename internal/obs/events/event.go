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

type base struct {
	ID Id
	Op Op
}
type Audit struct {
	*base
}

type Err struct {
	*base
}

type Info struct {
	*base
	Details map[string]interface{} `json:"details,omitempty"`
	Header  map[string]interface{} `json:"header,omitempty"`
}

func NewInfo(eventId string, fromOperation Op, opt ...Option) (*Info, error) {
	const op = "event.NewInfo"
	opts := getOpts(opt...)
	if eventId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "missing event id")
	}
	i := &Info{
		Header:  opts.withHeader,
		Details: opts.withDetails,
		base: &base{
			ID: Id(eventId),
			Op: fromOperation,
		},
	}
	return i, nil
}

func (i *Info) EventType() string { return string(InfoType) }
