// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package tcp_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_LookupTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)
	proj.Name = "project-name"
	ctx := context.Background()
	_, _, err := iamRepo.UpdateScope(ctx, proj, 1, []string{"name"})
	require.NoError(t, err)
	rw := db.New(conn)
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)
	tgt := tcp.TestTarget(ctx, t, conn, proj.PublicId, "target-name")

	tests := []struct {
		testName    string
		id          string
		name        string
		projectId   string
		projectName string
		wantErr     bool
	}{
		{
			testName: "id",
			id:       tgt.GetPublicId(),
			wantErr:  false,
		},
		{
			testName: "name only",
			name:     tgt.GetName(),
			wantErr:  true,
		},
		{
			testName:  "project id only",
			projectId: proj.PublicId,
			wantErr:   true,
		},
		{
			testName:    "project name only",
			projectName: proj.Name,
			wantErr:     true,
		},
		{
			testName:    "project name and id",
			projectId:   proj.PublicId,
			projectName: proj.Name,
			wantErr:     true,
		},
		{
			testName:    "everything",
			name:        tgt.GetName(),
			projectId:   proj.PublicId,
			projectName: proj.Name,
			wantErr:     true,
		},
		{
			testName:    "name and project name",
			name:        tgt.GetName(),
			projectName: proj.Name,
			wantErr:     false,
		},
		{
			testName:  "name and project id",
			name:      tgt.GetName(),
			projectId: proj.PublicId,
			wantErr:   false,
		},
		{
			testName:  "id and name",
			id:        tgt.GetPublicId(),
			name:      tgt.GetName(),
			projectId: proj.PublicId,
			wantErr:   true,
		},
		{
			testName:    "id and project name",
			id:          tgt.GetPublicId(),
			projectName: proj.Name,
			wantErr:     true,
		},
		{
			testName:  "id and project id",
			id:        tgt.GetPublicId(),
			projectId: proj.PublicId,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			id := tt.id
			if tt.name != "" && tt.id == "" {
				id = tt.name
			}
			var opts []target.Option
			if tt.name != "" {
				opts = append(opts, target.WithName(tt.name))
			}
			if tt.projectId != "" {
				opts = append(opts, target.WithProjectId(tt.projectId))
			}
			if tt.projectName != "" {
				opts = append(opts, target.WithProjectName(tt.projectName))
			}
			got, err := repo.LookupTarget(ctx, id, opts...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tgt.GetPublicId(), got.GetPublicId())
		})
	}
}

func TestRepository_DeleteTarget(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	_, proj := iam.TestScopes(t, iamRepo)

	ctx := context.Background()
	repo, err := target.NewRepository(ctx, rw, rw, testKms)
	require.NoError(t, err)

	type args struct {
		target target.Target
		opt    []target.Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				target: tcp.TestTarget(ctx, t, conn, proj.PublicId, "valid"),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				target: func() target.Target {
					tar, _ := target.New(ctx, tcp.Subtype, proj.PublicId)
					return tar
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "target.(Repository).DeleteTarget: missing public id: parameter violation: error #100",
		},
		{
			name: "not-found",
			args: args{
				target: func() target.Target {
					id, err := db.NewPublicId(ctx, globals.TcpTargetPrefix)
					require.NoError(t, err)
					tar, _ := target.New(ctx, tcp.Subtype, proj.PublicId)
					tar.SetPublicId(ctx, id)
					return tar
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "db.LookupById: record not found, search issue: error #1100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteTarget(ctx, tt.args.target.GetPublicId(), tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.IsNotFoundError(err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundGroup, err := repo.LookupTarget(ctx, tt.args.target.GetPublicId())
			assert.NoError(err)
			assert.Nil(foundGroup)

			err = db.TestVerifyOplog(t, rw, tt.args.target.GetPublicId(), db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)
		})
	}
}
