// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/sentinel"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	temp "github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCredential_New(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]
	lib := TestCredentialLibraries(t, conn, wrapper, cs.PublicId, globals.UnspecifiedCredentialType, 1)[0]
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
					Status:     string(ActiveCredential),
				},
			},
		},
		{
			name: "valid-no-external-id",
			args: args{
				libraryId:  lib.GetPublicId(),
				sessionId:  session.GetPublicId(),
				externalId: "",
				tokenHmac:  token.GetTokenHmac(),
				expiration: 5 * time.Minute,
			},
			want: &Credential{
				Credential: &store.Credential{
					LibraryId:  lib.GetPublicId(),
					SessionId:  session.GetPublicId(),
					ExternalId: sentinel.ExternalIdNone,
					TokenHmac:  token.GetTokenHmac(),
					Status:     string(UnknownCredentialStatus),
				},
			},
		},
		{
			name: "valid-no-expiration",
			args: args{
				libraryId:  lib.GetPublicId(),
				sessionId:  session.GetPublicId(),
				externalId: "some/vault/credential",
				tokenHmac:  token.GetTokenHmac(),
				expiration: 0,
			},
			want: &Credential{
				Credential: &store.Credential{
					LibraryId:      lib.GetPublicId(),
					SessionId:      session.GetPublicId(),
					ExternalId:     "some/vault/credential",
					TokenHmac:      token.GetTokenHmac(),
					ExpirationTime: timestamp.New(timestamp.PositiveInfinityTS),
					Status:         string(ActiveCredential),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			got, err := newCredential(ctx, tt.args.libraryId,
				tt.args.externalId, tt.args.tokenHmac, tt.args.expiration)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			assert.Emptyf(got.PublicId, "PublicId set")

			id, err := newCredentialId(ctx)
			assert.NoError(err)

			tt.want.PublicId = id
			got.PublicId = id

			query, queryValues := insertQuery(got, tt.args.sessionId)
			require.NoError(err)

			rows, err2 := rw.Exec(ctx, query, queryValues)
			assert.Equal(1, rows)
			assert.NoError(err2)

			got2 := allocCredential()
			got2.PublicId = id
			assert.Equal(id, got2.GetPublicId())
			require.NoError(rw.LookupById(ctx, got2))

			tt.want.LastRenewalTime = got2.LastRenewalTime
			tt.want.CreateTime = got2.CreateTime
			tt.want.UpdateTime = got2.UpdateTime
			tt.want.Version = got2.Version
			if tt.want.ExpirationTime == nil {
				tt.want.ExpirationTime = got2.ExpirationTime
			}

			assert.Empty(cmp.Diff(tt.want, got2.clone(), protocmp.Transform()))
		})
	}
}
