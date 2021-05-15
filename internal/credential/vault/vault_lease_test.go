package vault

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	temp "github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredential_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]
	lib := TestCredentialLibraries(t, conn, wrapper, cs.PublicId, 1)[0]
	token := cs.Token()

	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := temp.TestDefaultSession(t, conn, wrapper, iamRepo)

	type args struct {
		libraryId  string
		sessionId  string
		externalId string
		tokenHmac  []byte
		expiration time.Duration
	}

	tests := []struct {
		name    string
		args    args
		want    *Credential
		wantErr bool
	}{
		{
			name: "missing-library-id",
			args: args{
				sessionId:  session.GetPublicId(),
				externalId: "some/vault/credential",
				tokenHmac:  token.GetTokenHmac(),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-session-id",
			args: args{
				libraryId:  lib.GetPublicId(),
				externalId: "some/vault/credential",
				tokenHmac:  token.GetTokenHmac(),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-credential-id",
			args: args{
				libraryId:  lib.GetPublicId(),
				sessionId:  session.GetPublicId(),
				tokenHmac:  token.GetTokenHmac(),
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-tokenHmac",
			args: args{
				libraryId:  lib.GetPublicId(),
				sessionId:  session.GetPublicId(),
				externalId: "some/vault/credential",
				tokenHmac:  []byte{},
				expiration: 5 * time.Minute,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-expiration",
			args: args{
				libraryId:  lib.GetPublicId(),
				sessionId:  session.GetPublicId(),
				externalId: "some/vault/credential",
				tokenHmac:  token.GetTokenHmac(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				libraryId:  lib.GetPublicId(),
				sessionId:  session.GetPublicId(),
				externalId: "some/vault/credential",
				tokenHmac:  token.GetTokenHmac(),
				expiration: 5 * time.Minute,
			},
			want: &Credential{
				Credential: &store.Credential{
					LibraryId:  lib.GetPublicId(),
					SessionId:  session.GetPublicId(),
					ExternalId: "some/vault/credential",
					TokenHmac:  token.GetTokenHmac(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			got, err := newCredential(tt.args.libraryId, tt.args.sessionId,
				tt.args.externalId, tt.args.tokenHmac, tt.args.expiration)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")

			id, err := newCredentialId()
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			query, queryValues := got.insertQuery()

			rows, err2 := rw.Exec(ctx, query, queryValues)
			assert.Equal(1, rows)
			assert.NoError(err2)

			insertedCredential := allocCredential()
			insertedCredential.PublicId = id
			assert.Equal(id, insertedCredential.GetPublicId())
			require.NoError(rw.LookupById(ctx, insertedCredential))
		})
	}
}
