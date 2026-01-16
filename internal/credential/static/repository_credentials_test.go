// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"golang.org/x/crypto/ssh/testdata"
	"google.golang.org/protobuf/types/known/structpb"
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
	upCred1 := TestUsernamePasswordCredential(t, conn, wrapper, "user", "pass", staticStore.GetPublicId(), prj.GetPublicId())
	upCred2 := TestUsernamePasswordCredential(t, conn, wrapper, "different user", "better password", staticStore.GetPublicId(), prj.GetPublicId())
	updCred1 := TestUsernamePasswordDomainCredential(t, conn, wrapper, "user", "pass", "domain.com", staticStore.GetPublicId(), prj.GetPublicId())
	updCred2 := TestUsernamePasswordDomainCredential(t, conn, wrapper, "different user", "better password", "new-domain.com", staticStore.GetPublicId(), prj.GetPublicId())
	pCred1 := TestPasswordCredential(t, conn, wrapper, "better password", staticStore.GetPublicId(), prj.GetPublicId())
	pCred2 := TestPasswordCredential(t, conn, wrapper, "another password", staticStore.GetPublicId(), prj.GetPublicId())
	spkCred1 := TestSshPrivateKeyCredential(t, conn, wrapper, "final user", string(testdata.PEMBytes["ed25519"]), staticStore.GetPublicId(), prj.GetPublicId())
	spkCred2 := TestSshPrivateKeyCredential(t, conn, wrapper, "last user", string(testdata.PEMBytes["rsa-openssh-format"]), staticStore.GetPublicId(), prj.GetPublicId())
	spkCredWithPass := TestSshPrivateKeyCredential(t, conn, wrapper, "another last user",
		string(testdata.PEMEncryptedKeys[0].PEMBytes), staticStore.GetPublicId(), prj.GetPublicId(),
		WithPrivateKeyPassphrase([]byte(testdata.PEMEncryptedKeys[0].EncryptionKey)))

	obj, _ := TestJsonObject(t)

	secondObj := credential.JsonObject{
		Struct: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"username": structpb.NewStringValue("new-user"),
				"password": structpb.NewStringValue("new-password"),
				"hash":     structpb.NewStringValue("0987654321"),
			},
		},
	}

	jsonCred1 := TestJsonCredential(t, conn, wrapper, staticStore.GetPublicId(), prj.GetPublicId(), obj)
	jsonCred2 := TestJsonCredential(t, conn, wrapper, staticStore.GetPublicId(), prj.GetPublicId(), secondObj)

	type args struct {
		credIds   []string
		projectId string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantCreds []credential.Static
	}{
		{
			name: "no-project-id",
			args: args{
				credIds: []string{upCred1.GetPublicId()},
			},
			wantErr: true,
		},
		{
			name: "invalid-project-id",
			args: args{
				projectId: org.GetPublicId(),
				credIds:   []string{upCred1.GetPublicId()},
			},
			wantErr: true,
		},
		{
			name: "valid-one-up-cred",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{upCred1.GetPublicId()},
			},
			wantCreds: []credential.Static{
				upCred1,
			},
		},
		{
			name: "valid-multiple-up-creds",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{upCred1.GetPublicId(), upCred2.GetPublicId()},
			},
			wantCreds: []credential.Static{
				upCred1, upCred2,
			},
		},
		{
			name: "valid-one-upd-cred",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{updCred1.GetPublicId()},
			},
			wantCreds: []credential.Static{
				updCred1,
			},
		},
		{
			name: "valid-multiple-upd-creds",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{updCred1.GetPublicId(), updCred2.GetPublicId()},
			},
			wantCreds: []credential.Static{
				updCred1, updCred2,
			},
		},
		{
			name: "valid-one-p-cred",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{pCred1.GetPublicId()},
			},
			wantCreds: []credential.Static{
				pCred1,
			},
		},
		{
			name: "valid-multiple-p-creds",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{pCred1.GetPublicId(), pCred2.GetPublicId()},
			},
			wantCreds: []credential.Static{
				pCred1, pCred2,
			},
		},
		{
			name: "valid-ssh-pk-cred",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{spkCred1.GetPublicId()},
			},
			wantCreds: []credential.Static{
				spkCred1,
			},
		},
		{
			name: "valid-multiple-ssh-pk-creds",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{spkCred1.GetPublicId(), spkCred2.GetPublicId(), spkCredWithPass.GetPublicId()},
			},
			wantCreds: []credential.Static{
				spkCred1, spkCred2, spkCredWithPass,
			},
		},
		{
			name: "valid-json-cred",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{jsonCred1.GetPublicId()},
			},
			wantCreds: []credential.Static{
				jsonCred1,
			},
		},
		{
			name: "valid-multiple-json-creds",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{jsonCred1.GetPublicId(), jsonCred2.GetPublicId()},
			},
			wantCreds: []credential.Static{
				jsonCred1, jsonCred2,
			},
		},
		{
			name: "valid-mixed-creds",
			args: args{
				projectId: prj.GetPublicId(),
				credIds:   []string{upCred1.GetPublicId(), spkCred1.GetPublicId(), spkCredWithPass.GetPublicId(), spkCred2.GetPublicId(), upCred2.GetPublicId(), jsonCred1.GetPublicId(), jsonCred2.GetPublicId(), updCred1.GetPublicId(), updCred2.GetPublicId(), pCred1.GetPublicId(), pCred2.GetPublicId()},
			},
			wantCreds: []credential.Static{
				upCred1, spkCred1, spkCredWithPass, spkCred2, upCred2, jsonCred1, jsonCred2, updCred1, updCred2, pCred1, pCred2,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			gotCreds, err := repo.Retrieve(context.Background(), tt.args.projectId, tt.args.credIds)
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
					cmpopts.IgnoreUnexported(
						UsernamePasswordCredential{}, store.UsernamePasswordCredential{},
						UsernamePasswordDomainCredential{}, store.UsernamePasswordDomainCredential{},
						PasswordCredential{}, store.PasswordCredential{},
						SshPrivateKeyCredential{}, store.SshPrivateKeyCredential{},
						JsonCredential{}, store.JsonCredential{}),
					cmpopts.IgnoreTypes(&timestamp.Timestamp{}),
					cmpopts.IgnoreFields(SshPrivateKeyCredential{}, "PassphraseUnneeded"),
					cmpopts.SortSlices(func(x, y credential.Static) bool {
						return x.GetPublicId() < y.GetPublicId()
					}),
				),
			)
		})
	}
}
