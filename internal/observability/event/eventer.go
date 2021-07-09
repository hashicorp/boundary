package event

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/hashicorp/eventlogger"
	"github.com/hashicorp/eventlogger/filters/gated"
	"github.com/hashicorp/eventlogger/sinks/writer"

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
	sysPipeline         = "sys-pipeline"         // sysPipeline is a pipeline for system events
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
	sysEventer     *Eventer  // sysEventer is the system-wide Eventer
	sysEventerOnce sync.Once // sysEventerOnce ensures that the system-wide Eventer is only initialized once.
)

// InitSysEventer provides a mechanism to initialize a "system wide" eventer
// singleton for Boundary
func InitSysEventer(log hclog.Logger, c EventerConfig) error {
	const op = "event.InitSysEventer"
	if log == nil {
		return fmt.Errorf("%s: missing hclog: %w", op, ErrInvalidParameter)
	}
	// the order of operations is important here.  we want to determine if
	// there's an error before setting the singleton sysEventer which can only
	// be done one time.
	eventer, err := NewEventer(log, c)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	sysEventerOnce.Do(func() {
		sysEventer = eventer
	})
	return nil
}

// SysEventer returns the "system wide" eventer for Boundary.
func SysEventer() *Eventer {
	return sysEventer
}

// NewEventer creates a new Eventer using the config.  Supports options: WithNow
func NewEventer(log hclog.Logger, c EventerConfig, opt ...Option) (*Eventer, error) {
	const op = "event.NewEventer"
	if log == nil {
		return nil, fmt.Errorf("%s: missing logger: %w", op, ErrInvalidParameter)
	}

	// if there are no sinks in config, then we'll default to just one stdout
	// sink.
	if len(c.Sinks) == 0 {
		c.Sinks = append(c.Sinks, SinkConfig{
			Name:       "default",
			EventTypes: []Type{EveryType},
			Format:     JSONSinkFormat,
			SinkType:   StdoutSink,
		})
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	type pipeline struct {
		eventType Type
		fmtId     eventlogger.NodeID
		sinkId    eventlogger.NodeID
	}
	var auditPipelines, observationPipelines, errPipelines, sysPipelines []pipeline

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
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	jsonfmtId := eventlogger.NodeID(id)
	fmtNode := &eventlogger.JSONFormatter{}
	err = e.broker.RegisterNode(jsonfmtId, fmtNode)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to register json node: %w", op, err)
	}

	for _, s := range c.Sinks {
		var sinkId eventlogger.NodeID
		var sinkNode eventlogger.Node
		switch s.SinkType {
		case StdoutSink:
			sinkNode = &writer.Sink{
				Format: string(s.Format),
				Writer: os.Stdout,
			}
			id, err = newId("stdout")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			sinkId = eventlogger.NodeID(id)
		default:
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
				return nil, fmt.Errorf("%s: %w", op, err)
			}
			sinkId = eventlogger.NodeID(id)
		}
		err = e.broker.RegisterNode(sinkId, sinkNode)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register sink node %s: %w", op, sinkId, err)
		}
		var addToAudit, addToObservation, addToErr, addToSys bool
		for _, t := range s.EventTypes {
			switch t {
			case EveryType:
				addToAudit = true
				addToObservation = true
				addToErr = true
				addToSys = true
			case ErrorType:
				addToErr = true
			case AuditType:
				addToAudit = true
			case ObservationType:
				addToObservation = true
			case SystemType:
				addToSys = true
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
		if addToSys {
			sysPipelines = append(sysPipelines, pipeline{
				eventType: SystemType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
	}
	if c.AuditEnabled && len(auditPipelines) == 0 {
		return nil, fmt.Errorf("%s: audit events enabled but no sink defined for it: %w", op, ErrInvalidParameter)
	}
	if c.ObservationsEnabled && len(observationPipelines) == 0 {
		return nil, fmt.Errorf("%s: observation events enabled but no sink defined for it: %w", op, ErrInvalidParameter)
	}
	if c.SysEventsEnabled && len(sysPipelines) == 0 {
		return nil, fmt.Errorf("%s: system events enabled but no sink defined for it: %w", op, ErrInvalidParameter)
	}

	auditNodeIds := make([]eventlogger.NodeID, 0, len(auditPipelines))
	for _, p := range auditPipelines {
		gatedFilterNode := gated.Filter{}
		e.flushableNodes = append(e.flushableNodes, &gatedFilterNode)
		gateId, err := newId("gated-audit")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := e.broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, fmt.Errorf("%s: unable to register audit gated filter: %w", op, err)
		}

		pipeId, err := newId(auditPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{gatedFilterNodeId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register audit pipeline: %w", op, err)
		}
		auditNodeIds = append(auditNodeIds, p.sinkId)
	}
	observationNodeIds := make([]eventlogger.NodeID, 0, len(observationPipelines))
	for _, p := range observationPipelines {
		gatedFilterNode := gated.Filter{}
		e.flushableNodes = append(e.flushableNodes, &gatedFilterNode)
		gateId, err := newId("gated-observation")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := e.broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, fmt.Errorf("%s: unable to register audit gated filter: %w", op, err)
		}

		pipeId, err := newId(observationPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{gatedFilterNodeId, p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register observation pipeline: %w", op, err)
		}
		observationNodeIds = append(observationNodeIds, p.sinkId)
	}
	errNodeIds := make([]eventlogger.NodeID, 0, len(errPipelines))
	for _, p := range errPipelines {
		pipeId, err := newId(errPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register err pipeline: %w", op, err)
		}
		errNodeIds = append(errNodeIds, p.sinkId)
	}
	sysNodeIds := make([]eventlogger.NodeID, 0, len(sysPipelines))
	for _, p := range sysPipelines {
		pipeId, err := newId(sysPipeline)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		err = e.broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, fmt.Errorf("%s: failed to register sys pipeline: %w", op, err)
		}
		sysNodeIds = append(sysNodeIds, p.sinkId)
	}

	// TODO(jimlambrt) go-eventlogger SetSuccessThreshold currently does not
	// specify which sink passed and which hasn't so we are unable to
	// support multiple sinks with different delivery guarantees
	if c.AuditDelivery == Enforced {
		err = e.broker.SetSuccessThreshold(eventlogger.EventType(AuditType), len(auditNodeIds))
		if err != nil {
			return nil, fmt.Errorf("%s: failed to set success threshold for audit events: %w", op, err)
		}
	}
	if c.ObservationDelivery == Enforced {
		err = e.broker.SetSuccessThreshold(eventlogger.EventType(ObservationType), len(observationNodeIds))
		if err != nil {
			return nil, fmt.Errorf("%s: failed to set success threshold for observation events: %w", op, err)
		}
	}
	if c.SysEventsDelivery == Enforced {
		err = e.broker.SetSuccessThreshold(eventlogger.EventType(SystemType), len(sysNodeIds))
		if err != nil {
			return nil, fmt.Errorf("%s: failed to set success threshold for system events: %w", op, err)
		}
	}
	// always enforce delivery of errors
	err = e.broker.SetSuccessThreshold(eventlogger.EventType(ErrorType), len(errNodeIds))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to set success threshold for error events: %w", op, err)
	}

	return e, nil
}

// writeObservation writes/sends an Observation event.
func (e *Eventer) writeObservation(ctx context.Context, event *observation) error {
	const op = "event.(Eventer).writeObservation"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
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
		return e.broker.Send(ctx, eventlogger.EventType(ObservationType), event.Payload)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an observation event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// writeError writes/sends an Err event
func (e *Eventer) writeError(ctx context.Context, event *err) error {
	const op = "event.(Eventer).writeError"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(ErrorType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an error event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// writeSysEvent writes/sends an sysEvent event
func (e *Eventer) writeSysEvent(ctx context.Context, event *sysEvent) error {
	const op = "event.(Eventer).writeSysEvent"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(SystemType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an sys event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

// writeAudit writes/send an audit event
func (e *Eventer) writeAudit(ctx context.Context, event *audit) error {
	const op = "event.(Eventer).writeAudit"
	if event == nil {
		return fmt.Errorf("%s: missing event: %w", op, ErrInvalidParameter)
	}
	if !e.conf.AuditEnabled {
		return nil
	}
	err := e.retrySend(ctx, stdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(AuditType), event)
	})
	if err != nil {
		e.logger.Error("encountered an error sending an audit event", "error:", err.Error())
		return fmt.Errorf("%s: %w", op, err)
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
			return fmt.Errorf("%s: %w", op, err)
		}
	}
	return nil
}
