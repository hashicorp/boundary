package static

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_Retrieve(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	assert, require := assert.New(t), require.New(t)
	repo, err := NewRepository(context.Background(), rw, rw, kms)
	assert.NoError(err)
	require.NotNil(repo)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	staticStore := TestCredentialStore(t, conn, wrapper, prj.GetPublicId())
	cred1 := TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", staticStore.GetPublicId(), prj.GetPublicId())
	cred2 := TestUsernamePasswordCredential(t, conn, wrapper, "different user", "better password", staticStore.GetPublicId(), prj.GetPublicId())
	cred3 := TestUsernamePasswordCredential(t, conn, wrapper, "final user", "horrible password", staticStore.GetPublicId(), prj.GetPublicId())

	type args struct {
		credIds []string
		scopeId string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantCreds []credential.Static
	}{
		{
			name: "no-scope",
			args: args{
				credIds: []string{cred1.GetPublicId()},
			},
			wantErr: true,
		},
		{
			name: "invalid-scope",
			args: args{
				scopeId: org.GetPublicId(),
				credIds: []string{cred1.GetPublicId()},
			},
			wantErr: true,
		},
		{
			name: "valid-one-cred",
			args: args{
				scopeId: prj.GetPublicId(),
				credIds: []string{cred1.GetPublicId()},
			},
			wantCreds: []credential.Static{
				cred1,
			},
		},
		{
			name: "valid-multiple-creds",
			args: args{
				scopeId: prj.GetPublicId(),
				credIds: []string{cred1.GetPublicId(), cred2.GetPublicId(), cred3.GetPublicId()},
			},
			wantCreds: []credential.Static{
				cred1, cred2, cred3,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gotCreds, err := repo.Retrieve(context.Background(), tt.args.scopeId, tt.args.credIds)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(gotCreds)
				return
			}
			require.NoError(err)
			assert.Empty(
				cmp.Diff(
					tt.wantCreds,
					gotCreds,
					cmpopts.IgnoreUnexported(UsernamePasswordCredential{}, store.UsernamePasswordCredential{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					cmpopts.SortSlices(func(x, y credential.Static) bool {
						return x.GetPublicId() < y.GetPublicId()
					}),
				),
			)
		})
	}
}
