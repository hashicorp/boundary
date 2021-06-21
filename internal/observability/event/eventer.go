package event

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/go-hclog"
)

const (
	OpField          = "op"           // OpField in an event.
	RequestInfoField = "request_info" // RequestInfoField in an event.
	VersionField     = "version"      // VersionField in an event
	DetailsField     = "details"      // Details field in an event.
	HeaderField      = "header"       // HeaderField in an event.
	IdField          = "id"           // IdField in an event.
	CreatedAtField   = "created_at"   // CreatedAtField in an event.
	TypeField        = "type"         // TypeField in an event.

	auditPipeline       = "audit-pipeline"       // auditPipeline is a pipeline for audit events
	observationPipeline = "observation-pipeline" // observationPipeline is a pipeline for observation events
	errPipeline         = "err-pipeline"         // errPipeline is a pipeline for error events
)

// flushable defines an interface that all eventlogger Nodes must implement if
// they are "flushable"
type flushable interface {
	FlushAll(ctx context.Context) error
}

// broker defines an interface for an eventlogger Broker... which will allow us
// to substitute our testing broker when needed to write tests for things
// like event send retrying.
type broker interface {
	Send(ctx context.Context, t eventlogger.EventType, payload interface{}) (eventlogger.Status, error)
	Reopen(ctx context.Context) error
	StopTimeAt(now time.Time)
	RegisterNode(id eventlogger.NodeID, node eventlogger.Node) error
	SetSuccessThreshold(t eventlogger.EventType, successThreshold int) error
	RegisterPipeline(def eventlogger.Pipeline) error
}

// Eventer provides a method to send events to pipelines of sinks
type Eventer struct {
	broker         broker
	flushableNodes []flushable
	conf           EventerConfig
	logger         hclog.Logger
}

var (
	sysEventer     *Eventer   // sysEventer is the system-wide Eventer
	sysEventerLock sync.Mutex // sysEventerLock allows the sysEventer to safely be written concurrently.
)

// InitSysEventer provides a mechanism to initialize a "system wide" eventer
// singleton for Boundary.  Support the options of: WithEventer(...) and
// WithEventerConfig(...)
//
// IMPORTANT: Eventers cannot share file sinks, which likely means that each
// process should only have one Eventer.  In practice this means the process
// Server (Controller or Worker) and the SysEventer both need a pointer to a
// single Eventer.
func InitSysEventer(log hclog.Logger, opt ...Option) error {
	const op = "event.InitSysEventer"
	if log == nil {
		return errors.New(errors.InvalidParameter, op, "missing hclog")
	}

	// the order of operations is important here.  we want to determine if
	// there's an error before setting the singleton sysEventer
	var e *Eventer
	opts := getOpts(opt...)
	switch {
	case opts.withEventer == nil && opts.withEventerConfig == nil:
		return errors.New(errors.InvalidParameter, op, "missing both eventer and eventer config")

	case opts.withEventer != nil && opts.withEventerConfig != nil:
		return errors.New(errors.InvalidParameter, op, "both eventer and eventer config provided")

	case opts.withEventerConfig != nil:
		var err error
		if e, err = NewEventer(log, *opts.withEventerConfig); err != nil {
			return errors.Wrap(err, op)
		}

	case opts.withEventer != nil:
		e = opts.withEventer
	}

	sysEventerLock.Lock()
	defer sysEventerLock.Unlock()
	sysEventer = e
	return nil
}

// SysEventer returns the "system wide" eventer for Boundary and can/will return
// a nil Eventer
func SysEventer() *Eventer {
	return sysEventer
}

// NewEventer creates a new Eventer using the config.  Supports options: WithNow
func NewEventer(log hclog.Logger, c EventerConfig, opt ...Option) (*Eventer, error) {
	const op = "event.NewEventer"
	if log == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}

	// if there are no sinks in config, then we'll default to just one stderr
	// sink.
	if len(c.Sinks) == 0 {
		c.Sinks = append(c.Sinks, SinkConfig{
			Name:       "default",
			EventTypes: []Type{EveryType},
			Format:     JSONSinkFormat,
			SinkType:   StderrSink,
		})
	}

	if err := c.Validate(); err != nil {
		return nil, errors.Wrap(err, op)
	}

	type pipeline struct {
		eventType Type
		fmtId     eventlogger.NodeID
		sinkId    eventlogger.NodeID
	}
	var auditPipelines, observationPipelines, errPipelines []pipeline

	opts := getOpts(opt...)
	var b broker
	switch {
	case opts.withBroker != nil:
		b = opts.withBroker
	default:
		b = eventlogger.NewBroker()
	}

	e := &Eventer{
		logger: log,
		conf:   c,
		broker: b,
	}

	if !opts.withNow.IsZero() {
		e.broker.StopTimeAt(opts.withNow)
	}

	// Create JSONFormatter node
	id, err := newId("json")
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	jsonfmtId := eventlogger.NodeID(id)
	fmtNode := &eventlogger.JSONFormatter{}
	err = e.broker.RegisterNode(jsonfmtId, fmtNode)
	if err != nil {
		return nil, errors.Wrap(err, "failed to register json node")
	}

	// serializedStderr will be shared among all StderrSinks so their output is not
	// interwoven
	serializedStderr := serializedWriter{
		w: os.Stderr,
		l: new(sync.Mutex),
	}

	// we need to keep track of all the Sink filenames to ensure they aren't
	// reused.
	allSinkFilenames := map[string]bool{}

	for _, s := range c.Sinks {
		var sinkId eventlogger.NodeID
		var sinkNode eventlogger.Node
		switch s.SinkType {
		case StderrSink:
			sinkNode = &eventlogger.WriterSink{
				Format: string(s.Format),
				Writer: &serializedStderr,
			}
			id, err = newId("stderr")
			if err != nil {
				return nil, errors.Wrap(err, op)
			}
			sinkId = eventlogger.NodeID(id)
		default:
			if _, found := allSinkFilenames[s.Path+s.FileName]; found {
				return nil, errors.New(errors.InvalidParameter, op, fmt.Sprintf("Duplicate file sink: %s %s", s.Path, s.FileName))
			}
			sinkNode = &eventlogger.FileSink{
				Format:      string(s.Format),
				Path:        s.Path,
				FileName:    s.FileName,
				MaxBytes:    s.RotateBytes,
				MaxDuration: s.RotateDuration,
				MaxFiles:    s.RotateMaxFiles,
			}
			id, err = newId(fmt.Sprintf("file_%s_%s_", s.Path, s.FileName))
			if err != nil {
				return nil, errors.Wrap(err, op)
			}
			sinkId = eventlogger.NodeID(id)
		}
		err = e.broker.RegisterNode(sinkId, sinkNode)
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed to register sink node %s", sinkId)))
		}
		var addToAudit, addToObservation, addToErr bool
		for _, t := range s.EventTypes {
			switch t {
			case EveryType:
				addToAudit = true
				addToObservation = true
				addToErr = true
			case ErrorType:
				addToErr = true
			case AuditType:
				addToAudit = true
			case ObservationType:
				addToObservation = true
			}
		}
		if addToAudit {
			auditPipelines = append(auditPipelines, pipeline{
				eventType: AuditType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
		if addToObservation {
			observationPipelines = append(observationPipelines, pipeline{
				eventType: ObservationType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
		if addToErr {
			errPipelines = append(errPipelines, pipeline{
				eventType: ErrorType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
	}
	if c.AuditEnabled && len(auditPipelines) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "audit events enabled but no sink defined for it")
	}
	if c.ObservationsEnabled && len(observationPipelines) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "observation events enabled but no sink defined for it")
	}

	auditNodeIds := make([]eventlogger.NodeID, 0, len(auditPipelines))
	for _, p := range auditPipelines {
		gatedFilterNode := eventlogger.GatedFilter{}
		e.flushableNodes = append(e.flushableNodes, &gatedFilterNode)
		gateId, err := newId("gated-audit")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := e.broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to register audit gated filter"))
		}

		pipeId, err := newId(auditPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{gatedFilterNodeId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register audit pipeline")
		}
		auditNodeIds = append(auditNodeIds, p.sinkId)
	}
	observationNodeIds := make([]eventlogger.NodeID, 0, len(observationPipelines))
	for _, p := range observationPipelines {
		gatedFilterNode := eventlogger.GatedFilter{}
		e.flushableNodes = append(e.flushableNodes, &gatedFilterNode)
		gateId, err := newId("gated-observation")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := e.broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to register audit gated filter"))
		}

		pipeId, err := newId(observationPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{gatedFilterNodeId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register observation pipeline")
		}
		observationNodeIds = append(observationNodeIds, p.sinkId)
	}
	errNodeIds := make([]eventlogger.NodeID, 0, len(errPipelines))
	for _, p := range errPipelines {
		pipeId, err := newId(errPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register err pipeline")
		}
		errNodeIds = append(errNodeIds, p.sinkId)
	}

	// always enforce delivery of errors
	err = e.broker.SetSuccessThreshold(eventlogger.EventType(ErrorType), len(errNodeIds))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set success threshold for error events")
	}

	return e, nil
}

// writeObservation writes/sends an Observation event.
func (e *Eventer) writeObservation(ctx context.Context, event *observation) error {
	const op = "event.(Eventer).writeObservation"
	if event == nil {
		return errors.New(errors.InvalidParameter, op, "missing event")
	}
	if !e.conf.ObservationsEnabled {
		return nil
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		if event.Header != nil {
			event.Header[RequestInfoField] = event.RequestInfo
			event.Header[VersionField] = event.Version
		}
		if event.Detail != nil {
			event.Detail[OpField] = string(event.Op)
		}
		return e.broker.Send(ctx, eventlogger.EventType(ObservationType), event.SimpleGatedPayload)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an observation event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// writeError writes/sends an Err event
func (e *Eventer) writeError(ctx context.Context, event *err) error {
	const op = "event.(Eventer).writeError"
	if event == nil {
		return errors.New(errors.InvalidParameter, op, "missing event")
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(ErrorType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an error event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// writeAudit writes/send an audit event
func (e *Eventer) writeAudit(ctx context.Context, event *audit) error {
	const op = "event.(Eventer).writeAudit"
	if event == nil {
		return errors.New(errors.InvalidParameter, op, "missing event")
	}
	if !e.conf.AuditEnabled {
		return nil
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(AuditType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an audit event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// Reopen can used during a SIGHUP to reopen nodes, most importantly the underlying
// file sinks.
func (e *Eventer) Reopen() error {
	if e.broker != nil {
		return e.broker.Reopen(context.Background())
	}
	return nil
}

// FlushNodes will flush any of the eventer's flushable nodes.  This
// needs to be called whenever Boundary is stopping (aka shutting down).
func (e *Eventer) FlushNodes(ctx context.Context) error {
	const op = "event.(Eventer).FlushNodes"
	for _, n := range e.flushableNodes {
		if err := n.FlushAll(ctx); err != nil {
			return errors.Wrap(err, op)
		}
	}
	return nil
}
