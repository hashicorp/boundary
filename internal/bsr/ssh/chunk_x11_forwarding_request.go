// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/internal/is"
	gssh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

const X11ForwardingRequestType = "x11-req"

// X11ForwardingRequest is a chunk to contain data for an SSH X11 Forwarding request
type X11ForwardingRequest struct {
	*bsr.BaseChunk
	*pssh.X11ForwardingRequest
}

// MarshalData serializes an X11ForwardingRequest chunk
func (r *X11ForwardingRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(X11ForwardingRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.X11ForwardingRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewX11ForwardingRequest creates an X11ForwardingRequest chunk
func NewX11ForwardingRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*X11ForwardingRequest, error) {
	const op = "ssh.NewX11ForwardingRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != X11ForwardingRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, X11ForwardingRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, X11ForwardingReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval x11ForwardingSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &X11ForwardingRequest{
		BaseChunk: baseChunk,
		X11ForwardingRequest: &pssh.X11ForwardingRequest{
			RequestType:               r.Type,
			WantReply:                 r.WantReply,
			SingleConnection:          sigval.SingleConnection,
			X11AuthenticationProtocol: sigval.X11AuthenticationProtocol,
			X11AuthenticationCookie:   sigval.X11AuthenticationCookie,
			X11ScreenNumber:           sigval.X11ScreenNumber,
		},
	}
	return reqData, nil
}

type x11ForwardingSigval struct {
	SingleConnection          bool
	X11AuthenticationProtocol string
	X11AuthenticationCookie   string
	X11ScreenNumber           uint32
}
