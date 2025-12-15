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

// A CredentialLibrary is a CredentialSource that represents the relationship
// between a target and a credential library.
type CredentialLibrary struct {
	*store.CredentialLibrary
	CredentialType string `gorm:"-"` // The credential library's issuing credential type.
	tableName      string `gorm:"-"`
}

// NewCredentialLibrary creates a new in memory CredentialLibrary
// representing the relationship between targetId and credentialLibraryId.
func NewCredentialLibrary(ctx context.Context, targetId, credentialLibraryId string, purpose credential.Purpose, credType string) (*CredentialLibrary, error) {
	const op = "target.NewCredentialLibrary"
	if targetId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no target id")
	}
	if credentialLibraryId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no credential library id")
	}

	t := &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{
			TargetId:            targetId,
			CredentialLibraryId: credentialLibraryId,
			CredentialPurpose:   string(purpose),
		},
		CredentialType: credType,
	}
	return t, nil
}

func allocCredentialLibrary() *CredentialLibrary {
	return &CredentialLibrary{
		CredentialLibrary: &store.CredentialLibrary{},
	}
}

func (t *CredentialLibrary) clone() *CredentialLibrary {
	cp := proto.Clone(t.CredentialLibrary)
	return &CredentialLibrary{
		CredentialLibrary: cp.(*store.CredentialLibrary),
	}
}

// TableName returns the table name.
func (t *CredentialLibrary) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return "target_credential_library"
}

// SetTableName sets the table name.
func (t *CredentialLibrary) SetTableName(n string) {
	t.tableName = n
}

func (t *CredentialLibrary) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{fmt.Sprintf("%s:%s:%s", t.TargetId, t.CredentialLibraryId, t.CredentialPurpose)},
		"resource-type":      []string{"target-credential-library"},
		"op-type":            []string{op.String()},
	}
	return metadata
}
