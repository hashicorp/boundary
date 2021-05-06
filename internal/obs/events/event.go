package event

import (
	"time"
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
	Timestamp time.Time
	ID        Id
	Op        Op
}
type Audit struct {
	*base
}

type Err struct {
	*base
}

type Info struct {
	*base
	details map[string]interface{}
	header  map[string]interface{}
}

func NewInfo(id Id, op Op, opt ...Option) (*Info, error) {
	opts := getOpts(opt...)
	i := &Info{
		header:  opts.withHeader,
		details: opts.withDetails,
		base: &base{
			ID:        id,
			Op:        op,
			Timestamp: time.Now(),
		},
	}
	return i, nil
}

func (i *Info) EventType() string { return string(InfoType) }
