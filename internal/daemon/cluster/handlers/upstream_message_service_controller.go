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
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var upstreamMessageHandler *sync.Map = new(sync.Map)

// UpstreamMessageHandler defines a handler for an UpstreamMessageRequest(s).
//
// See controllerUpstreamMessageServiceServer.UpstreamMessage for how this is
// used to handle an UpstreamMessageRequest via registered upstream message
// handlers.
type UpstreamMessageHandler interface {
	// Handler for the request.  All errors returned must be a error created
	// using google.golang.org/grpc/status
	Handler(ctx context.Context, request proto.Message) (response proto.Message, statusErr error)
	UpstreamMessageTypeSpecifier
}

// RegisterUpstreamMessageHandler will register an UpstreamMessageHandler for
// the specified msg name.
//
// See controllerUpstreamMessageServiceServer.UpstreamMessage for how this is
// used to handle an UpstreamMessageRequest via registered upstream message
// handlers.
func RegisterUpstreamMessageHandler(ctx context.Context, msgType pbs.MsgType, h UpstreamMessageHandler) error {
	const op = "handlers.RegisterUpstreamMessageHandler"
	switch {
	case msgType == pbs.MsgType_MSG_TYPE_UNSPECIFIED:
		return errors.New(ctx, errors.InvalidParameter, op, "missing msg type")
	case util.IsNil(h):
		return errors.New(ctx, errors.InvalidParameter, op, "missing handler")
	}
	upstreamMessageHandler.Store(msgType, h)
	if err := registerUpstreamMessageTypeSpecifier(ctx, msgType, h); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func getUpstreamMessageHandler(ctx context.Context, msgType pbs.MsgType) (UpstreamMessageHandler, bool) {
	const op = "handlers.getUpstreamMessageHandler"
	switch {
	case msgType == pbs.MsgType_MSG_TYPE_UNSPECIFIED:
		event.WriteError(ctx, op, fmt.Errorf("missing msg type"))
		return nil, false
	}
	v, ok := upstreamMessageHandler.Load(msgType)
	if !ok {
		return nil, false
	}

	h, ok := v.(UpstreamMessageHandler)
	if !ok {
		event.WriteError(ctx, op, fmt.Errorf("malformed handler type %q registered as incorrect type %T", msgType.String(), v))
		return nil, false
	}
	return h, true
}

// controllerUpstreamMessageServiceServer implements the
// UpstreamMessageServiceServer for OSS controllers
type controllerUpstreamMessageServiceServer struct {
	pbs.UnimplementedUpstreamMessageServiceServer
	storage nodeenrollment.Storage
}

var _ pbs.UpstreamMessageServiceServer = (*controllerUpstreamMessageServiceServer)(nil)

// NewControllerUpstreamMessageServiceServer creates a new service implementing
// UpstreamMessageServiceServer, storing values used for the implementing
// functions.
func NewControllerUpstreamMessageServiceServer(
	ctx context.Context,
	storage nodeenrollment.Storage,
) (pbs.UpstreamMessageServiceServer, error) {
	const op = "handlers.NewControllerUpstreamMessageServiceServer"
	switch {
	case util.IsNil(storage):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing storage")
	}

	return &controllerUpstreamMessageServiceServer{
		storage: storage,
	}, nil
}

// UpstreamMessage implements the grpc service of the same name for controllers.
// It decrypts the request using the originating workers ID using its
// types.NodeCredentials. If there's a registered UpstreamMessageHandler for the
// underlying message's protoreflect.FullName; then the msg is handled by the
// handler otherwise an codes.Unimplemented status error is returned
func (s *controllerUpstreamMessageServiceServer) UpstreamMessage(ctx context.Context, req *pbs.UpstreamMessageRequest) (*pbs.UpstreamMessageResponse, error) {
	const op = "handlers.(controllerUpstreamMessageServiceServer).UpstreamMessage"
	switch {
	case req == nil:
		return nil, status.Errorf(codes.Internal, "%s: missing request", op)
	case req.GetOriginatingWorkerKeyId() == "":
		return nil, status.Errorf(codes.Internal, "%s: missing originating worker id", op)
	case req.GetMsgType() == pbs.MsgType_MSG_TYPE_UNSPECIFIED:
		return nil, status.Errorf(codes.Internal, "%s: msg type %q is unsupported", op, req.GetMsgType().String())
	}

	h, ok := getUpstreamMessageHandler(ctx, req.GetMsgType())
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "upstream message handler for %q is not implemented", req.GetMsgType().String())
	}

	msg := h.AllocRequest()
	var nodeInfo *types.NodeInformation

	switch {
	case h.Encrypted() == false:
		if err := proto.Unmarshal(req.GetPt(), msg); err != nil {
			return nil, status.Errorf(codes.Internal, "%s: error marshaling request message: %v", op, err)
		}
	default:
		var err error
		nodeInfo, err = types.LoadNodeInformation(ctx, s.storage, req.OriginatingWorkerKeyId)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%s: error loading node information: %v", op, err)
		}
		if nodeInfo == nil {
			return nil, status.Errorf(codes.Internal, "%s: no error loading worker pki auth creds but nil creds, returning error", op)
		}
		if err := nodeenrollment.DecryptMessage(ctx, req.GetCt(), nodeInfo, msg); err != nil {
			return nil, status.Errorf(codes.Internal, "%s: error decrypting request message: %v", op, err)
		}
	}
	clonedMsg := proto.Clone(msg)
	if err := event.WriteAudit(ctx, "handlers.(controllerUpstreamMessageServiceServer).UpstreamMessage",
		event.WithRequest(
			&event.Request{
				DetailsUpstreamMessage: &event.UpstreamMessage{
					Message: clonedMsg,
					Type:    string(clonedMsg.ProtoReflect().Descriptor().Name()),
				},
			},
		)); err != nil {
		// error was NOT event'd above...
		_ = errors.Wrap(ctx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("error writing upstream message unwrapped details request"))
	}
	respMsg, respStatusErr := h.Handler(ctx, msg)
	if respStatusErr != nil {
		return nil, respStatusErr
	}
	clonedResp := proto.Clone(respMsg)
	if err := event.WriteAudit(ctx, "handlers.(controllerUpstreamMessageServiceServer).UpstreamMessage",
		event.WithResponse(
			&event.Response{
				DetailsUpstreamMessage: &event.UpstreamMessage{
					Message: clonedResp,
					Type:    string(clonedResp.ProtoReflect().Descriptor().Name()),
				},
			},
		)); err != nil {
		// error was NOT event'd above...
		_ = errors.Wrap(ctx, err, op, errors.WithCode(errors.Internal), errors.WithMsg("error writing upstream message unwrapped details response"))
	}
	switch {
	case h.Encrypted() == false:
		pt, err := proto.Marshal(respMsg)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%s: error marshaling response: %v", op, err)
		}
		return &pbs.UpstreamMessageResponse{
			Message: &pbs.UpstreamMessageResponse_Pt{
				Pt: pt,
			},
		}, nil
	default:
		ct, err := nodeenrollment.EncryptMessage(ctx, respMsg, nodeInfo)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%s: error encrypting response: %v", op, err)
		}
		return &pbs.UpstreamMessageResponse{
			Message: &pbs.UpstreamMessageResponse_Ct{
				Ct: ct,
			},
		}, nil
	}
}
