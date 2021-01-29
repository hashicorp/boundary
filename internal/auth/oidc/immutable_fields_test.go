package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthMethod_ImmutableFields(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	new := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, TestConvertToUrls(t, "https://alice.com")[0], "alice_rp", "my-dogs-name")

	tests := []struct {
		name      string
		update    *AuthMethod
		fieldMask []string
	}{
		{
			name: "public_id",
			update: func() *AuthMethod {
				cp := new.Clone()
				cp.PublicId = "p_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *AuthMethod {
				cp := new.Clone()
				cp.CreateTime = &ts
				return cp
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "scope_id",
			update: func() *AuthMethod {
				cp := new.Clone()
				cp.ScopeId = "o_thisIsNotAValidId"
				return cp
			}(),
			fieldMask: []string{"ScopeId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			orig := new.Clone()
			orig.SetTableName(DefaultAuthMethodTableName)
			err := rw.LookupById(context.Background(), orig)
			require.NoError(err)

			tt.update.SetTableName(DefaultAuthMethodTableName)
			rowsUpdated, err := rw.Update(context.Background(), tt.update, tt.fieldMask, nil, db.WithSkipVetForWrite(true))
			require.Error(err)
			assert.Equal(0, rowsUpdated)

			after := new.Clone()
			after.SetTableName(DefaultAuthMethodTableName)
			err = rw.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))
		})
	}
}
