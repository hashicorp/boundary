package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicCredential_New(t *testing.T) {
	t.Parallel()

	type args struct {
		sessionId    string
		credentialId string
		library      *target.CredentialLibrary
	}
	tests := []struct {
		name    string
		args    args
		want    *DynamicCredential
		wantErr errors.Code
	}{
		{
			name: "empty-sessionId",
			args: args{
				sessionId: "",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "empty-credentialId",
			args: args{
				sessionId: "abcd_OOOOOOOOOO",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "nil-library",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "empty-library",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library:      &target.CredentialLibrary{},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "library-empty-library-id",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library: &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						CredentialPurpose: "application",
					},
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "library-empty-purpose",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library: &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						CredentialLibraryId: "library_1",
					},
				},
			},
			wantErr: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				sessionId:    "abcd_OOOOOOOOOO",
				credentialId: "cred_OOOOOOOOOO",
				library: &target.CredentialLibrary{
					CredentialLibrary: &store.CredentialLibrary{
						TargetId:            "target_1",
						CredentialLibraryId: "library_1",
						CredentialPurpose:   "application",
					},
				},
			},
			want: &DynamicCredential{
				SessionId:         "abcd_OOOOOOOOOO",
				CredentialId:      "cred_OOOOOOOOOO",
				LibraryId:         "library_1",
				CredentialPurpose: "application",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewDynamicCredential(tt.args.sessionId, tt.args.credentialId, tt.args.library)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}
}

func TestDynamicCredential_Write(t *testing.T) {
	t.Parallel()
	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		wrapper := db.TestWrapper(t)
		kms := kms.TestKms(t, conn, wrapper)
		iamRepo := iam.TestRepo(t, conn, wrapper)

		o, p := iam.TestScopes(t, iamRepo)
		at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
		uId := at.GetIamUserId()
		hc := static.TestCatalogs(t, conn, p.GetPublicId(), 1)[0]
		hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
		h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
		static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

		cs := vault.TestCredentialStores(t, conn, wrapper, p.GetPublicId(), 1)[0]
		cl := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

		tar := target.TestTcpTarget(t, conn, p.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))
		tcl := target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId())

		sess := TestSession(t, conn, wrapper, ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ScopeId:     p.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})

		vaultCred := vault.TestLeases(t, conn, wrapper, cl.GetPublicId(), sess.GetPublicId(), 1)[0]
		sessionCred, err := NewDynamicCredential(sess.GetPublicId(), vaultCred.GetPublicId(), tcl)
		assert.NoError(err)
		require.NotNil(sessionCred)

		rw := db.New(conn)
		require.NoError(rw.Create(ctx, sessionCred))
	})
}
