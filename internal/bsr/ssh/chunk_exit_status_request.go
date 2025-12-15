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

const ExitStatusRequestType = "exit-status"

// ExitStatusRequest is a chunk to contain data for an SSH Exit Status request
type ExitStatusRequest struct {
	*bsr.BaseChunk
	*pssh.ExitStatusRequest
}

// MarshalData serializes an ExitStatusRequest chunk
func (r *ExitStatusRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(ExitStatusRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.ExitStatusRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewExitSignalRequest creates an ExitSignalRequest chunk
func NewExitStatusRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*ExitStatusRequest, error) {
	const op = "ssh.NewExitStatusRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != ExitStatusRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, ExitStatusRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ExitStatusReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval exitStatusSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &ExitStatusRequest{
		BaseChunk: baseChunk,
		ExitStatusRequest: &pssh.ExitStatusRequest{
			RequestType: r.Type,
			WantReply:   r.WantReply,
			ExitStatus:  sigval.ExitStatus,
		},
	}
	return reqData, nil
}

type exitStatusSigval struct {
	ExitStatus uint32
}
