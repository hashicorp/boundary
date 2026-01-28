// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

// A StaticCredential is a CredentialSource that represents the relationship
// between a target and a static credential.
type StaticCredential struct {
	*store.StaticCredential
	tableName string `gorm:"-"`
}

// NewStaticCredential creates a new in memory StaticCredential
// representing the relationship between targetId and credentialId.
func NewStaticCredential(ctx context.Context, targetId, credentialId string, purpose credential.Purpose) (*StaticCredential, error) {
	const op = "target.StaticCredential"
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no target id")
	}
	if credentialId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no credential id")
	}

	t := &StaticCredential{
		StaticCredential: &store.StaticCredential{
			TargetId:          targetId,
			CredentialId:      credentialId,
			CredentialPurpose: string(purpose),
		},
	}
	return t, nil
}

func (t *StaticCredential) clone() *StaticCredential {
	cp := proto.Clone(t.StaticCredential)
	return &StaticCredential{
		StaticCredential: cp.(*store.StaticCredential),
	}
}

// TableName returns the table name.
func (t *StaticCredential) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return "target_static_credential"
}

// SetTableName sets the table name.
func (t *StaticCredential) SetTableName(n string) {
	t.tableName = n
}

func (t *StaticCredential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{fmt.Sprintf("%s:%s:%s", t.TargetId, t.CredentialId, t.CredentialPurpose)},
		"resource-type":      []string{"target-credential-static"},
		"op-type":            []string{op.String()},
	}
	return metadata
}
