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

type SinkType string
type SinkFormat string
type DeliveryGuarantee string

const (
	StdoutSink     SinkType          = "stdout"
	FileSink       SinkType          = "file"
	JSONSinkFormat SinkFormat        = "json"
	Enforced       DeliveryGuarantee = "enforced"
	BestEffort     DeliveryGuarantee = "best-effort"
	AuditPipeline                    = "audit-pipeline"
	InfoPipeline                     = "info-pipeline"
	ErrPipeline                      = "err-pipeline"
)

type Eventer struct {
	broker *eventlogger.Broker
	conf   Config
	logger hclog.Logger
	l      sync.Mutex
}

type SinkConfig struct {
	Name           string
	EventTypes     []Type
	SinkType       SinkType
	Format         SinkFormat
	Path           string
	FileName       string
	RotateBytes    int
	RotateDuration time.Duration
	RotateMaxFiles int
}

type Config struct {
	AuditDelivery DeliveryGuarantee
	InfoDelivery  DeliveryGuarantee
	AuditEnabled  bool
	InfoEnabled   bool
	Sinks         []SinkConfig
}

func NewEventer(log hclog.Logger, c Config) (*Eventer, error) {
	const op = "event.NewEventer"
	if log == nil {
		return nil, errors.New(errors.InvalidParameter, op, "missing logger")
	}

	type pipeline struct {
		eventType Type
		fmtId     eventlogger.NodeID
		sinkId    eventlogger.NodeID
	}
	var auditPipelines, infoPipelines, errPipelines []pipeline
	broker := eventlogger.NewBroker()

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
		var addToAudit, addToInfo, addToErr bool
		for _, t := range s.EventTypes {
			switch t {
			case EveryType:
				addToAudit = true
				addToInfo = true
				addToErr = true
			case ErrorType:
				addToErr = true
			case AuditType:
				addToAudit = true
			case InfoType:
				addToInfo = true
			}
		}
		if addToAudit {
			auditPipelines = append(auditPipelines, pipeline{
				eventType: AuditType,
				fmtId:     jsonfmtId,
				sinkId:    sinkId,
			})
		}
		if addToInfo {
			infoPipelines = append(infoPipelines, pipeline{
				eventType: InfoType,
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

	auditNodeIds := make([]eventlogger.NodeID, 0, len(auditPipelines))
	for _, p := range auditPipelines {
		id, err = newId("audit-pipeline")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(id),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register audit pipeline")
		}
		auditNodeIds = append(auditNodeIds, p.sinkId)
	}
	infoNodeIds := make([]eventlogger.NodeID, 0, len(infoPipelines))
	for _, p := range infoPipelines {
		id, err = newId("info-pipeline")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(id),
			NodeIDs:    []eventlogger.NodeID{p.fmtId, p.sinkId},
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to register info pipeline")
		}
		infoNodeIds = append(infoNodeIds, p.sinkId)
	}
	errNodeIds := make([]eventlogger.NodeID, 0, len(errPipelines))
	for _, p := range errPipelines {
		id, err = newId("err-pipeline")
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		err = broker.RegisterPipeline(eventlogger.Pipeline{
			EventType:  eventlogger.EventType(p.eventType),
			PipelineID: eventlogger.PipelineID(id),
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
	if c.InfoDelivery == Enforced {
		err = broker.SetSuccessThreshold(eventlogger.EventType(InfoType), len(infoNodeIds))
		if err != nil {
			return nil, errors.Wrap(err, "failed to set success threshold for info events")
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

func (e *Eventer) Info(ctx context.Context, event *Info, opt ...Option) error {
	const op = "event.(Eventer).Info"
	if !e.conf.InfoEnabled {
		return nil
	}
	status, err := e.broker.Send(ctx, eventlogger.EventType(InfoType), event)
	if err != nil {
		e.logger.Error("encountered an error sending an info event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	if len(status.Warnings) > 0 {
		e.logger.Warn("encountered warnings send info event", "warnings:", status.Warnings)
	}
	return nil
}

func (e *Eventer) Error(ctx context.Context, event *Err, opt ...Option) error {
	const op = "event.(Eventer).Error"
	status, err := e.broker.Send(ctx, eventlogger.EventType(ErrorType), event)
	if err != nil {
		e.logger.Error("encountered an error sending an error event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	if len(status.Warnings) > 0 {
		e.logger.Warn("encountered warnings send error event", "warnings:", status.Warnings)
	}
	return nil
}

func (e *Eventer) Audit(ctx context.Context, event *Audit, opt ...Option) error {
	const op = "event.(Eventer).Audit"
	if !e.conf.AuditEnabled {
		return nil
	}
	status, err := e.broker.Send(ctx, eventlogger.EventType(InfoType), event)
	if err != nil {
		e.logger.Error("encountered an error sending an audit event", "error:", err.Error())
		return errors.Wrap(err, op)
	}
	if len(status.Warnings) > 0 {
		e.logger.Warn("encountered warnings send audit event", "warnings:", status.Warnings)
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
