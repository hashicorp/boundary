package target

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/protobuf/proto"
)

// A CredentialStatic is a CredentialSource that represents the relationship
// between a target and a credential static.
type CredentialStatic struct {
	*store.CredentialStatic
	tableName string `gorm:"-"`
}

// NewCredentialStatic creates a new in memory CredentialStatic
// representing the relationship between targetId and credentialStaticId.
func NewCredentialStatic(targetId, credentialStaticId string, purpose credential.Purpose) (*CredentialStatic, error) {
	const op = "target.NewCredentialStatic"
	if targetId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no target id")
	}
	if credentialStaticId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no credential static id")
	}

	t := &CredentialStatic{
		CredentialStatic: &store.CredentialStatic{
			TargetId:           targetId,
			CredentialStaticId: credentialStaticId,
			CredentialPurpose:  string(purpose),
		},
	}
	return t, nil
}

func allocCredentialStatic() *CredentialStatic {
	return &CredentialStatic{
		CredentialStatic: &store.CredentialStatic{},
	}
}

func (t *CredentialStatic) clone() *CredentialStatic {
	cp := proto.Clone(t.CredentialStatic)
	return &CredentialStatic{
		CredentialStatic: cp.(*store.CredentialStatic),
	}
}

// TableName returns the table name.
func (t *CredentialStatic) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return "target_credential_static"
}

// SetTableName sets the table name.
func (t *CredentialStatic) SetTableName(n string) {
	t.tableName = n
}

func (t *CredentialStatic) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{fmt.Sprintf("%s:%s:%s", t.TargetId, t.CredentialStaticId, t.CredentialPurpose)},
		"resource-type":      []string{"target-credential-static"},
		"op-type":            []string{op.String()},
	}
	return metadata
}
