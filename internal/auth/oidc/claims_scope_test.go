package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestClaimsScope_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	type args struct {
		authMethodId string
		claimsScope  string
	}
	tests := []struct {
		name               string
		args               args
		createResource     bool
		createWantErrMatch *errors.Template
		want               *ClaimsScope
		wantErrMatch       *errors.Template
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewClaimsScope(tt.args.authMethodId, tt.args.claimsScope)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted error %s and got: %s", tt.wantErrMatch.Code, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.createResource {
				err := rw.Create(ctx, got)
				if tt.createWantErrMatch != nil {
					require.Error(err)
					assert.Truef(errors.Match(tt.createWantErrMatch, err), "wanted error %s and got: %s", tt.wantErrMatch.Code, err.Error())
					return
				}
				assert.NoError(err)
				found := AllocClaimsScope()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and scope = ?", tt.args.authMethodId, tt.args.claimsScope))
			}
		})
	}
}

func TestClaimsScope_Clone(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewClaimsScope(m.PublicId, "profile")
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.ClaimsScope, orig.ClaimsScope))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewClaimsScope(m.PublicId, "email")
		require.NoError(err)
		orig2, err := NewClaimsScope(m.PublicId, "profile")
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.ClaimsScope, orig2.ClaimsScope))
	})
}

func TestClaimsScope_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultClaimsScopeTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocClaimsScope()
			require.Equal(defaultTableName, def.TableName())
			m := AllocClaimsScope()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}
