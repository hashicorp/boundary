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

const ShellRequestType = "shell"

// ShellRequest is a chunk to contain data for an SSH Shell request
type ShellRequest struct {
	*bsr.BaseChunk
	*pssh.ShellRequest
}

// MarshalData serializes an ShellRequest chunk
func (r *ShellRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(SessionRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.ShellRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewShellRequest creates an ShellRequest chunk
func NewShellRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*ShellRequest, error) {
	const op = "ssh.NewShellRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != ShellRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, ShellRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, ShellReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	reqData := &ShellRequest{
		BaseChunk: baseChunk,
		ShellRequest: &pssh.ShellRequest{
			RequestType: r.Type,
			WantReply:   r.WantReply,
		},
	}
	return reqData, nil
}
