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
	OpField          = "op"
	RequestInfoField = "request_info"
	VersionField     = "version"
)

type SinkType string
type SinkFormat string
type DeliveryGuarantee string

const (
	StdoutSink          SinkType          = "stdout"
	FileSink            SinkType          = "file"
	JSONSinkFormat      SinkFormat        = "json"
	Enforced            DeliveryGuarantee = "enforced"
	BestEffort          DeliveryGuarantee = "best-effort"
	AuditPipeline                         = "audit-pipeline"
	ObservationPipeline                   = "observation-pipeline"
	ErrPipeline                           = "err-pipeline"
)

// Eventer provides a method to send events to pipelines of sinks
type Eventer struct {
	broker *eventlogger.Broker
	conf   EventerConfig
	logger hclog.Logger
	l      sync.Mutex
}

// SinkConfig defines the configuration for a Eventer sink
type SinkConfig struct {
	// Name defines a name for the sink.
	Name string

	// EventTypes defines a list of event types that will be sent to the sink.
	// See the docs for EventTypes for a list of accepted values.
	EventTypes     []Type
	SinkType       SinkType
	Format         SinkFormat
	Path           string
	FileName       string
	RotateBytes    int
	RotateDuration time.Duration
	RotateMaxFiles int
}

// EventerConfig supplies all the configuration needed to create/config an Eventer.
type EventerConfig struct {
	AuditDelivery       DeliveryGuarantee
	ObservationDelivery DeliveryGuarantee
	AuditEnabled        bool
	ObservationsEnabled bool
	Sinks               []SinkConfig
}

var sysEventer *Eventer
var sysEventerOnce sync.Once

// InitSysEventer provides a mechanism to initialize a "system wide" eventer
// singleton for Boundary
func InitSysEventer(log hclog.Logger, c EventerConfig) error {
	const op = "event.InitSysEventer"
	if log == nil {
		return errors.New(errors.InvalidParameter, op, "missing hclog")
	}
	// the order of operations is important here.  we want to determine if
	// there's an error before setting the singleton sysEventer which can only
	// be done one time.
	eventer, err := NewEventer(log, c)
	if err != nil {
		return errors.Wrap(err, op)
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

// NewEventer creates a new Eventer using the config
func NewEventer(log hclog.Logger, c EventerConfig, opt ...Option) (*Eventer, error) {
	const op = "event.NewEventer"
	if log == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}

	type pipeline struct {
		eventType Type
		fmtId     eventlogger.NodeID
		sinkId    eventlogger.NodeID
	}
	var auditPipelines, observationPipelines, errPipelines []pipeline

	broker := eventlogger.NewBroker()
	opts := getOpts(opt...)
	if !opts.withNow.IsZero() {
		broker.StopTimeAt(opts.withNow)
	}

	// Create JSONFormatter node
	id, err := newId("json")
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	jsonfmtId := eventlogger.NodeID(id)
	fmtNode := &eventlogger.JSONFormatter{}
	err = broker.RegisterNode(jsonfmtId, fmtNode)
	if err != nil {
		return nil, errors.Wrap(err, "failed to register json node")
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

	for _, s := range c.Sinks {
		var sinkId eventlogger.NodeID
		var sinkNode eventlogger.Node
		switch s.SinkType {
		case StdoutSink:
			sinkNode = &eventlogger.WriterSink{
				Format: string(s.Format),
				Writer: os.Stdout,
			}
			id, err = newId("stdout")
			if err != nil {
				return nil, errors.Wrap(err, op)
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
				return nil, errors.Wrap(err, op)
			}
			sinkId = eventlogger.NodeID(id)
		}
		err = broker.RegisterNode(sinkId, sinkNode)
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
		gateId, err := newId("gated-audit")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to register audit gated filter"))
		}

		pipeId, err := newId(AuditPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
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
		gateId, err := newId("gated-audit")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		gatedFilterNodeId := eventlogger.NodeID(gateId)
		if err := broker.RegisterNode(gatedFilterNodeId, &gatedFilterNode); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to register audit gated filter"))
		}

		pipeId, err := newId(ObservationPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
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
		pipeId, err := newId(ErrPipeline)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(pipeId),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register err pipeline")
		}
		errNodeIds = append(errNodeIds, p.sinkId)
	}

	// TODO(jimlambrt) go-eventlogger SetSuccessThreshold currently does not
	// specify which sink passed and which hasn't so we are unable to
	// support multiple sinks with different delivery guarantees
	if c.AuditDelivery == Enforced {
		err = broker.SetSuccessThreshold(eventlogger.EventType(AuditType), len(auditNodeIds))
		if err != nil {
			return nil, errors.Wrap(err, "failed to set success threshold for audit events")
		}
	}
	if c.ObservationDelivery == Enforced {
		err = broker.SetSuccessThreshold(eventlogger.EventType(ObservationType), len(observationNodeIds))
		if err != nil {
			return nil, errors.Wrap(err, "failed to set success threshold for observation events")
		}
	}
	// always enforce delivery of errors
	err = broker.SetSuccessThreshold(eventlogger.EventType(ErrorType), len(errNodeIds))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set success threshold for error events")
	}

	return &Eventer{
		logger: log,
		conf:   c,
		broker: broker,
	}, nil
}

// writeObservation writes/sends an Observation event.
func (e *Eventer) writeObservation(ctx context.Context, event *observation) error {
	const op = "event.(Eventer).WriteObservation"
	if !e.conf.ObservationsEnabled {
		return nil
	}
	err := e.retrySend(ctx, StdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		if event.Header != nil {
			event.Header[OpField] = string(event.Op)
			event.Header[RequestInfoField] = event.RequestInfo
			event.Header[VersionField] = event.Version
		}
		return e.broker.Send(ctx, eventlogger.EventType(ObservationType), event.SimpleGatedPayload)
	})
	if err != nil {
		e.logError("encountered an error sending an observation event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// writeError writes/sends an Err event
func (e *Eventer) writeError(ctx context.Context, event *err) error {
	const op = "event.(Eventer).WriteError"
	err := e.retrySend(ctx, StdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(ErrorType), event)
	})
	if err != nil {
		e.logError("encountered an error sending an error event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// writeAudit writes/send an audit event
func (e *Eventer) writeAudit(ctx context.Context, event *audit) error {
	const op = "event.(Eventer).WriteAudit"
	if !e.conf.AuditEnabled {
		return nil
	}
	err := e.retrySend(ctx, StdRetryCount, expBackoff{}, func() (eventlogger.Status, error) {
		return e.broker.Send(ctx, eventlogger.EventType(ObservationType), event)
	})
	if err != nil {
		e.logError("encountered an error sending an audit event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	return nil
}

// Reopen can used during a SIGHUP to reopen nodes, most importantly the underlying
// file sinks.
func (e *Eventer) Reopen() error {
	e.l.Lock()
	defer e.l.Unlock()
	return e.broker.Reopen(context.Background())
}

func (e *Eventer) logError(msg string, args ...interface{}) {
	if e.logger != nil {
		e.logger.Error(msg, args)
	}
}

func (e *Eventer) logWarning(msg string, args ...interface{}) {
	if e.logger != nil {
		e.logger.Warn(msg, args)
	}
}
