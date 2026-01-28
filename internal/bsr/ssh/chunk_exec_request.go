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

const ExecRequestType = "exec"

// ExecRequest is a chunk to contain data for an SSH Exec request
type ExecRequest struct {
	*bsr.BaseChunk
	*pssh.ExecRequest
}

// MarshalData serializes an ExecRequest chunk
func (r *ExecRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(ExecRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.ExecRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewExecRequest creates an ExecRequest chunk
func NewExecRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*ExecRequest, error) {
	const op = "ssh.NewExecRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != ExecRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, ExecRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ExecReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval execSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &ExecRequest{
		BaseChunk: baseChunk,
		ExecRequest: &pssh.ExecRequest{
			RequestType: r.Type,
			WantReply:   r.WantReply,
			Command:     sigval.Command,
		},
	}
	return reqData, nil
}

type execSigval struct {
	Command string
}
