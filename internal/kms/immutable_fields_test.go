package kms

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestExternalConfig_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	org, _ := iam.TestScopes(t, conn)
	new := TestExternalConfig(t, conn, org.PublicId, DevKms.String(), "{}")

	var tests = []struct {
		name      string
		update    *ExternalConfig
		fieldMask []string
	}{
		{
			name: "private_id",
			update: func() *ExternalConfig {
				c := new.Clone().(*ExternalConfig)
				c.PrivateId = "o_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PrivateId"},
		},
		{
			name: "create time",
			update: func() *ExternalConfig {
				c := new.Clone().(*ExternalConfig)
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "type",
			update: func() *ExternalConfig {
				c := new.Clone().(*ExternalConfig)
				c.Type = UnknownKms.String()
				return c
			}(),
			fieldMask: []string{"Type"},
		},
		{
			name: "scope_id",
			update: func() *ExternalConfig {
				c := new.Clone().(*ExternalConfig)
				c.ScopeId = "o_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.Clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig.(*ExternalConfig), after.(*ExternalConfig)))

		})
	}
}

// TODO (jimlambrt 8/2020) define tests for immutable fields in the remaining
// kms tables:
// 	kms_root_key
//	kms_root_key_version
//	kms_database_key
//	kms_database_key_version
//	kms_oplog_key
//	kms_oplog_key_version
//	kms_session_key
//	kms_session_key_version
