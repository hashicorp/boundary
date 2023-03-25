// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package handlers

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// UpstreamMessageServiceClientProducer produces a client and should be
// self-healing if an existing grpc connection closes.
type UpstreamMessageServiceClientProducer func(context.Context) (pbs.UpstreamMessageServiceClient, error)

// workerUpstreamMessageServiceServer implements the
// SessionRecordingServiceServer for workers and always forwards requests using
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
	h, ok := getUpstreamMessageHandler(ctx, msgType)
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "upstream message handler for %q is not implemented", msgType.String())
	}

	var req *pbs.UpstreamMessageRequest
	switch {
	case h.Encrypted() == false:
		req, err = ptMsg(ctx, msgType, msg)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	default:
		if opts.withNodeInfo == nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "missing node information required for encrypting unwrap keys message")
		}
		req, err = ctMsg(ctx, opts.withNodeInfo, msgType, msg)
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
	case h.Encrypted() == false:
		pt := h.AllocResponse()
		if err := proto.Unmarshal(rawResp.GetPt(), pt); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error marshaling echo request"))
		}
		return pt, nil
	default:
		ct := h.AllocResponse()
		if err := nodeenrollment.DecryptMessage(ctx, rawResp.GetCt(), opts.withNodeInfo, ct); err != nil {
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

func ctMsg(ctx context.Context, nodeInfo *types.NodeInformation, msgType pbs.MsgType, msg proto.Message) (*pbs.UpstreamMessageRequest, error) {
	const op = "handlers.encryptMsg"
	ct, err := nodeenrollment.EncryptMessage(ctx, msg, nodeInfo)
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

func toMsgType(ctx context.Context, m proto.Message) (pbs.MsgType, error) {
	const op = "handlers.toMsgType"
	switch t := m.(type) {
	case *pbs.EchoUpstreamMessageRequest, *pbs.EchoUpstreamMessageResponse:
		return pbs.MsgType_MSG_TYPE_ECHO, nil
	case *pbs.UnwrapKeysRequest, *pbs.UnwrapKeysResponse:
		return pbs.MsgType_MSG_TYPE_UNWRAP_KEYS, nil
	case *pbs.VerifySignatureRequest, *pbs.VerifySignatureResponse:
		return pbs.MsgType_MSG_TYPE_VERIFY_SIGNATURE, nil
	default:
		return pbs.MsgType_MSG_TYPE_UNSPECIFIED, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q is an unknown msg type", t))
	}
}
