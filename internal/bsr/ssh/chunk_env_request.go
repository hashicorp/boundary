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

const EnvRequestType = "env"

// EnvRequest is a chunk to contain data for an SSH Env request
type EnvRequest struct {
	*bsr.BaseChunk
	*pssh.EnvRequest
}

// MarshalData serializes an EnvRequest chunk
func (r *EnvRequest) MarshalData(ctx context.Context) ([]byte, error) {
	const op = "ssh.(EnvRequest).MarshalData"
	dataBytes, err := proto.Marshal(r.EnvRequest)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal data: %w", op, err)
	}

	d := make([]byte, 0, len(dataBytes))
	d = append(d, dataBytes...)

	return d, nil
}

// NewEnvRequest creates an EnvRequest chunk
func NewEnvRequest(ctx context.Context, d bsr.Direction, t *bsr.Timestamp, r *gssh.Request) (*EnvRequest, error) {
	const op = "ssh.NewEnvRequest"

	if is.Nil(r) {
		return nil, fmt.Errorf("%s: request cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}
	if r.Type != EnvRequestType {
		return nil, fmt.Errorf("%s: request type must be %q: %w", op, EnvRequestType, bsr.ErrInvalidParameter)
	}
	if !bsr.ValidDirection(d) {
		return nil, fmt.Errorf("%s: invalid direction: %w", op, bsr.ErrInvalidParameter)
	}
	if is.Nil(t) {
		return nil, fmt.Errorf("%s: timestamp cannot be nil: %w", op, bsr.ErrInvalidParameter)
	}

	baseChunk, err := bsr.NewBaseChunk(ctx, Protocol, d, t, EnvReqChunkType)
	if err != nil {
		return nil, fmt.Errorf("%s: unable to create base chunk: %w", op, err)
	}

	var sigval envSigval
	if err := gssh.Unmarshal(r.Payload, &sigval); err != nil {
		return nil, fmt.Errorf("%s: unable to unmarshal payload: %w", op, err)
	}
	reqData := &EnvRequest{
		BaseChunk: baseChunk,
		EnvRequest: &pssh.EnvRequest{
			RequestType:   r.Type,
			WantReply:     r.WantReply,
			VariableName:  sigval.Name,
			VariableValue: sigval.Value,
		},
	}
	return reqData, nil
}

type envSigval struct {
	Name  string
	Value string
}
