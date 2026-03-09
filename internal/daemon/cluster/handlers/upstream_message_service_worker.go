// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// UpstreamMessageServiceClientProducer produces a client and should be
// self-healing if an existing grpc connection closes.
type UpstreamMessageServiceClientProducer func(context.Context) (pbs.UpstreamMessageServiceClient, error)

// workerUpstreamMessageServiceServer implements the
// UpstreamMessageServiceServer for workers and always forwards requests using
// its clients
type workerUpstreamMessageServiceServer struct {
	pbs.UnimplementedUpstreamMessageServiceServer
	clientProducer UpstreamMessageServiceClientProducer
}

var _ pbs.UpstreamMessageServiceServer = (*workerUpstreamMessageServiceServer)(nil)

// NewWorkerUpstreamMessageServiceServer creates a new service implementing
// UpstreamMessageServiceServer, storing values used for the implementing
// functions.
func NewWorkerUpstreamMessageServiceServer(
	ctx context.Context,
	clientProducer UpstreamMessageServiceClientProducer,
) (*workerUpstreamMessageServiceServer, error) {
	const op = "handlers.NewWorkerUpstreamMessageServiceServer"
	switch {
	case clientProducer == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing client producer")
	}

	return &workerUpstreamMessageServiceServer{
		clientProducer: clientProducer,
	}, nil
}

// UpstreamMessage implements the grpc service of the same name for workers and
// simply forwards the request using its client
func (s *workerUpstreamMessageServiceServer) UpstreamMessage(ctx context.Context, req *pbs.UpstreamMessageRequest) (*pbs.UpstreamMessageResponse, error) {
	const op = "handlers.(workerUpstreamMessageServiceServer).UpstreamMessage"
	switch {
	case req == nil:
		return nil, status.Errorf(codes.Internal, "%s: missing request", op)
	}
	c, err := s.clientProducer(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s: unable to get client: %v", op, err)
	}
	return c.UpstreamMessage(ctx, req)
}

// UpstreamMessageTypeSpecifier defines an interface for specifying type
// information for an UpstreamMessageRequest(s).
//
// See handlers.SendUpstreamMessage for how this is
// used to send an UpstreamMessageRequest via registered upstream message
// type specifiers.
type UpstreamMessageTypeSpecifier interface {
	// Encrypted returns true if the request/response should be encrypted
	Encrypted() bool

	// AllocRequest will allocate a type specific request proto message
	AllocRequest() proto.Message

	// AllocResponse will allocate a type specific response proto message
	AllocResponse() proto.Message
}

var upstreamMessageTypeSpecifier *sync.Map = new(sync.Map)

// registerUpstreamMessageTypeSpecifier will register an
// UpstreamMessageTypeSpecifier for the specified msg name.
//
// See handlers.SendUpstreamMessage for how this is
// used to send UpstreamMessage requests
func registerUpstreamMessageTypeSpecifier(ctx context.Context, msgType pbs.MsgType, t UpstreamMessageTypeSpecifier) error {
	const op = "handlers.registerUpstreamMessageTypeSpecifier"
	switch {
	case msgType == pbs.MsgType_MSG_TYPE_UNSPECIFIED:
		return errors.New(ctx, errors.InvalidParameter, op, "missing msg type")
	case util.IsNil(t):
		return errors.New(ctx, errors.InvalidParameter, op, "missing type specifier")
	}
	upstreamMessageTypeSpecifier.Store(msgType, t)
	return nil
}

func getUpstreamMessageTypeSpecifier(ctx context.Context, msgType pbs.MsgType) (UpstreamMessageTypeSpecifier, bool) {
	const op = "handlers.getUpstreamMessageTypeSpecifier"
	switch {
	case msgType == pbs.MsgType_MSG_TYPE_UNSPECIFIED:
		event.WriteError(ctx, op, fmt.Errorf("missing msg type"))
		return nil, false
	}
	v, ok := upstreamMessageTypeSpecifier.Load(msgType)
	if !ok {
		return nil, false
	}

	h, ok := v.(UpstreamMessageTypeSpecifier)
	if !ok {
		event.WriteError(ctx, op, fmt.Errorf("malformed type specifier %q registered as incorrect type %T", msgType.String(), v))
		return nil, false
	}
	return h, true
}

func SendUpstreamMessage(ctx context.Context, clientProducer UpstreamMessageServiceClientProducer, originatingWorkerKeyId string, msg proto.Message, opt ...Option) (proto.Message, error) {
	const op = "handlers.SendUpstreamMessage"
	switch {
	case clientProducer == nil:
		return nil, status.Errorf(codes.Internal, "%s: missing client producer", op)
	case originatingWorkerKeyId == "":
		return nil, status.Errorf(codes.Internal, "%s: missing originating worker key id", op)
	case util.IsNil(msg):
		return nil, status.Errorf(codes.Internal, "%s: missing message", op)
	}
	opts := getOpts(opt...)

	msgType, err := toMsgType(ctx, msg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s: %v", op, err)
	}
	t, ok := getUpstreamMessageTypeSpecifier(ctx, msgType)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "upstream message type specifier for %q is not implemented", msgType.String())
	}

	var req *pbs.UpstreamMessageRequest
	switch {
	case t.Encrypted() == false:
		req, err = ptMsg(ctx, msgType, msg)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	default:
		if opts.withKeyProducer == nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing node information required for encrypting unwrap keys message")
		}
		req, err = ctMsg(ctx, opts.withKeyProducer, msgType, msg)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	req.OriginatingWorkerKeyId = originatingWorkerKeyId

	c, err := clientProducer(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error getting a client producer"))
	}

	rawResp, err := c.UpstreamMessage(ctx, req)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error from upstream client"))
	}

	switch {
	case t.Encrypted() == false:
		pt := t.AllocResponse()
		if err := proto.Unmarshal(rawResp.GetPt(), pt); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error marshaling echo request"))
		}
		return pt, nil
	default:
		ct := t.AllocResponse()
		if err := nodeenrollment.DecryptMessage(ctx, rawResp.GetCt(), opts.withKeyProducer, ct); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error decrypting unwrap keys response"))
		}
		return ct, nil
	}
}

func ptMsg(ctx context.Context, msgType pbs.MsgType, msg proto.Message) (*pbs.UpstreamMessageRequest, error) {
	const op = "handlers.ptMsg"

	pt, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error marshaling upstream message"))
	}
	return &pbs.UpstreamMessageRequest{
		MsgType: msgType,
		Message: &pbs.UpstreamMessageRequest_Pt{
			Pt: pt,
		},
	}, nil
}

func ctMsg(ctx context.Context, keySource nodeenrollment.X25519KeyProducer, msgType pbs.MsgType, msg proto.Message) (*pbs.UpstreamMessageRequest, error) {
	const op = "handlers.encryptMsg"
	ct, err := nodeenrollment.EncryptMessage(ctx, msg, keySource)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error encrypting upstream message"))
	}
	return &pbs.UpstreamMessageRequest{
		MsgType: msgType,
		Message: &pbs.UpstreamMessageRequest_Ct{
			Ct: ct,
		},
	}, nil
}

var entMsgTypeResolver func(ctx context.Context, m proto.Message) (pbs.MsgType, error)

func toMsgType(ctx context.Context, m proto.Message) (pbs.MsgType, error) {
	const op = "handlers.toMsgType"
	switch t := m.(type) {
	case *pbs.EchoUpstreamMessageRequest, *pbs.EchoUpstreamMessageResponse:
		return pbs.MsgType_MSG_TYPE_ECHO, nil
	default:
		if entMsgTypeResolver != nil {
			return entMsgTypeResolver(ctx, m)
		}
		return pbs.MsgType_MSG_TYPE_UNSPECIFIED, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q is an unknown msg type", t))
	}
}
