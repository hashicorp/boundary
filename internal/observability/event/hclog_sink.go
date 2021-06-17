package event

import (
	"context"
	"errors"

	"github.com/fatih/structs"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
)

type HclogSink struct {
	Logger hclog.Logger
}

func (fs *HclogSink) Reopen() error { return nil }

func (fs *HclogSink) Type() eventlogger.NodeType {
	return eventlogger.NodeTypeSink
}

func (fs *HclogSink) Process(ctx context.Context, e *eventlogger.Event) (*eventlogger.Event, error) {
	if fs.Logger == nil {
		return nil, errors.New("sink logger is nil")
	}
	if e == nil {
		return nil, errors.New("event is nil")
	}

	m := structs.Map(e.Payload)
	args := make([]interface{}, 0, len(m))
	for k, v := range structs.Map(e.Payload) {
		args = append(args, k, v)
	}

	fs.Logger.Info(string(e.Type)+" event", args...)

	// Sinks are leafs, so do not return the event, since nothing more can
	// happen to it downstream.
	return nil, nil
}
