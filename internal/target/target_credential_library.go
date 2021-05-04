package target

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

// A TargetCredentialLibrary represents the relationship between a target
// and a credential library.
type TargetCredentialLibrary struct {
	*store.TargetCredentialLibrary
	tableName string `gorm:"-"`
}

// NewTargetCredentialLibrary creates a new in memory
// TargetCredentialLibrary representing the relationship between targetId
// and credentialLibraryId.
func NewTargetCredentialLibrary(targetId, credentialLibraryId string, _ ...Option) (*TargetCredentialLibrary, error) {
	const op = "target.NewTargetCredentialLibrary"
	if targetId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no target id")
	}
	if credentialLibraryId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no credential library id")
	}

	t := &TargetCredentialLibrary{
		TargetCredentialLibrary: &store.TargetCredentialLibrary{
			TargetId:            targetId,
			CredentialLibraryId: credentialLibraryId,
			CredentialPurpose:   "application", // application is the only purpose currently supported
		},
	}
	return t, nil
}

func allocTargetCredentialLibrary() *TargetCredentialLibrary {
	return &TargetCredentialLibrary{
		TargetCredentialLibrary: &store.TargetCredentialLibrary{},
	}
}

func (t *TargetCredentialLibrary) clone() *TargetCredentialLibrary {
	cp := proto.Clone(t.TargetCredentialLibrary)
	return &TargetCredentialLibrary{
		TargetCredentialLibrary: cp.(*store.TargetCredentialLibrary),
	}
}

// TableName returns the table name.
func (t *TargetCredentialLibrary) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return "target_credential_library"
}

// SetTableName sets the table name.
func (t *TargetCredentialLibrary) SetTableName(n string) {
	t.tableName = n
}

func (t *TargetCredentialLibrary) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{fmt.Sprintf("%s:%s:%s", t.TargetId, t.CredentialLibraryId, t.CredentialPurpose)},
		"resource-type":      []string{"target-credential-library"},
		"op-type":            []string{op.String()},
	}
	return metadata
}
