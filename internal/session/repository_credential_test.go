// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_AddSessionCredentials(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	s := TestSession(t, conn, wrapper, TestSessionParams(t, conn, wrapper, iamRepo))

	type args struct {
		creds            []Credential
		sessionId        string
		sessionProjectId string
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name: "invalid-missing-credentials",
			args: args{
				sessionId:        s.PublicId,
				sessionProjectId: s.ProjectId,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).AddSessionCredentials: missing credentials: parameter violation: error #100",
		},
		{
			name: "invalid-missing-project-id",
			args: args{
				sessionId: s.PublicId,
				creds: []Credential{
					Credential("test-cred"),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).AddSessionCredentials: missing session project id: parameter violation: error #100",
		},
		{
			name: "invalid-missing-session-id",
			args: args{
				sessionProjectId: s.ProjectId,
				creds: []Credential{
					Credential("test-cred"),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).AddSessionCredentials: missing session id: parameter violation: error #100",
		},
		{
			name: "invalid-empty-cred",
			args: args{
				sessionId:        s.PublicId,
				sessionProjectId: s.ProjectId,
				creds: []Credential{
					Credential(""),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).AddSessionCredentials: missing credential: parameter violation: error #100",
		},
		{
			name: "invalid-empty-cred-with-valid",
			args: args{
				sessionId:        s.PublicId,
				sessionProjectId: s.ProjectId,
				creds: []Credential{
					Credential("test-cred"),
					Credential(""),
					Credential("test-cred2"),
				},
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).AddSessionCredentials: missing credential: parameter violation: error #100",
		},
		{
			name: "valid",
			args: args{
				sessionId:        s.PublicId,
				sessionProjectId: s.ProjectId,
				creds: []Credential{
					Credential("test-cred"),
					Credential("test-cred1"),
					Credential("test-cred2"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			err := repo.AddSessionCredentials(context.Background(), tt.args.sessionProjectId, tt.args.sessionId, tt.args.creds)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)

			creds, err := repo.ListSessionCredentials(context.Background(), s.ProjectId, s.PublicId)
			require.NoError(err)
			assert.ElementsMatch(creds, tt.args.creds)
		})
	}
}

func TestRepository_ListSessionCredentials(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	ctx := context.Background()
	repo, err := NewRepository(ctx, rw, rw, kms)
	require.NoError(t, err)
	s1 := TestSession(t, conn, wrapper, TestSessionParams(t, conn, wrapper, iamRepo))
	s2 := TestSession(t, conn, wrapper, TestSessionParams(t, conn, wrapper, iamRepo))
	s3 := TestSession(t, conn, wrapper, TestSessionParams(t, conn, wrapper, iamRepo))

	s1Creds := []Credential{
		Credential("cred1"),
		Credential("cred2"),
		Credential("cred3"),
	}
	s2Creds := []Credential{
		Credential("cred1"),
	}

	err = repo.AddSessionCredentials(context.Background(), s1.ProjectId, s1.PublicId, s1Creds)
	require.NoError(t, err)

	err = repo.AddSessionCredentials(context.Background(), s2.ProjectId, s2.PublicId, s2Creds)
	require.NoError(t, err)

	type args struct {
		sessionId        string
		sessionProjectId string
	}
	tests := []struct {
		name        string
		args        args
		wantCreds   []Credential
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name: "invalid-missing-project-id",
			args: args{
				sessionId: s1.PublicId,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).ListSessionCredentials: missing session project id: parameter violation: error #100",
		},
		{
			name: "invalid-missing-session-id",
			args: args{
				sessionProjectId: s1.ProjectId,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "session.(Repository).ListSessionCredentials: missing session id: parameter violation: error #100",
		},
		{
			name: "valid-s1",
			args: args{
				sessionId:        s1.PublicId,
				sessionProjectId: s1.ProjectId,
			},
			wantCreds: s1Creds,
		},
		{
			name: "valid-s2",
			args: args{
				sessionId:        s2.PublicId,
				sessionProjectId: s2.ProjectId,
			},
			wantCreds: s2Creds,
		},
		{
			name: "valid-s3-no-creds",
			args: args{
				sessionId:        s3.PublicId,
				sessionProjectId: s3.ProjectId,
			},
			wantCreds: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			creds, err := repo.ListSessionCredentials(context.Background(), tt.args.sessionProjectId, tt.args.sessionId)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.ElementsMatch(creds, tt.wantCreds)
		})
	}
}
