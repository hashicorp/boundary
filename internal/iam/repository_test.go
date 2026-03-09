// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	iam_store "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/oplog/store"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	testKms := kms.TestKms(t, conn, wrapper)
	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
	}
	tests := []struct {
		name          string
		args          args
		want          *Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r:   rw,
				w:   rw,
				kms: testKms,
			},
			want: &Repository{
				reader:       rw,
				writer:       rw,
				kms:          testKms,
				defaultLimit: db.DefaultLimit,
			},
			wantErr: false,
		},
		{
			name: "nil-kms",
			args: args{
				r:   rw,
				w:   rw,
				kms: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "iam.NewRepository: nil kms: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r:   rw,
				w:   nil,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "iam.NewRepository: nil writer: parameter violation: error #100",
		},
		{
			name: "nil-reader",
			args: args{
				r:   nil,
				w:   rw,
				kms: testKms,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "iam.NewRepository: nil reader: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(context.Background(), tt.args.r, tt.args.w, tt.args.kms)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantErrString, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func Test_Repository_create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s, err := NewOrg(ctx, WithName("fname-"+id))
		assert.NoError(err)
		s.PublicId, err = newScopeId(ctx, scope.Org)
		require.NoError(err)
		retScope, err := repo.create(ctx, s)
		require.NoError(err)
		require.NotNil(retScope)
		assert.NotEmpty(retScope.GetPublicId())
		assert.Equal(retScope.GetName(), "fname-"+id)

		foundScope, err := repo.LookupScope(ctx, s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, retScope.(*Scope)))

		var metadata store.Metadata
		err = rw.LookupWhere(ctx, &metadata, "key = ? and value = ?", []any{"resource-public-id", s.PublicId})
		require.NoError(err)

		var foundEntry oplog.Entry
		err = rw.LookupWhere(ctx, &foundEntry, "id = ?", []any{metadata.EntryId})
		assert.NoError(err)
	})
	t.Run("nil-resource", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		resource, err := repo.create(ctx, nil)
		require.Error(err)
		assert.Nil(resource)
		assert.Equal("iam.(Repository).create: missing resource: parameter violation: error #100", err.Error())
	})
}

func Test_Repository_delete(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-org", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		rw := db.New(conn)

		s, _ := TestScopes(t, repo)

		rowsDeleted, err := repo.delete(context.Background(), s)
		require.NoError(err)
		assert.Equal(1, rowsDeleted)

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(5*time.Second))
		require.NoError(err)
	})
	kms.TestKmsDeleteAllKeys(t, conn)

	t.Run("nil-resource", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		deletedRows, err := repo.delete(context.Background(), nil, nil)
		require.Error(err)
		assert.Equal(0, deletedRows)
		assert.Equal("iam.(Repository).delete: missing resource: parameter violation: error #100", err.Error())
	})
}

func TestRepository_update(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	now := &timestamp.Timestamp{Timestamp: timestamppb.Now()}
	id := testId(t)
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)
	repo := TestRepo(t, conn, wrapper)
	publicId := testPublicId(t, "o")

	type args struct {
		resource       Resource
		fieldMaskPaths []string
		setToNullPaths []string
		opt            []Option
	}
	tests := []struct {
		name            string
		args            args
		wantName        string
		wantDescription string
		wantUpdatedRows int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid-scope",
			args: args{
				resource: &Scope{
					Scope: &iam_store.Scope{
						Name:        "valid-scope" + id,
						Description: "updated" + id,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Name"},
				setToNullPaths: []string{"Description"},
			},
			wantName:        "valid-scope" + id,
			wantDescription: "",
			wantUpdatedRows: 1,
			wantErr:         false,
			wantErrMsg:      "",
		},
		{
			name: "nil-resource",
			args: args{
				resource:       nil,
				fieldMaskPaths: []string{"Name"},
				setToNullPaths: []string{"Description"},
			},
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "iam.(Repository).update: missing resource: parameter violation: error #100",
		},
		{
			name: "intersection",
			args: args{
				resource: &Scope{
					Scope: &iam_store.Scope{
						Name:        "intersection" + id,
						Description: "updated" + id,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Name"},
				setToNullPaths: []string{"Name"},
			},
			wantUpdatedRows: 0,
			wantErr:         true,
			wantErrMsg:      "fieldMashPaths and setToNullPaths cannot intersect: invalid parameter",
		},
		{
			name: "only-field-masks",
			args: args{
				resource: &Scope{
					Scope: &iam_store.Scope{
						Name:        "only-field-masks" + id,
						Description: "updated" + id,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: []string{"Name"},
				setToNullPaths: nil,
			},
			wantName:        "only-field-masks" + id,
			wantDescription: "orig-" + id,
			wantUpdatedRows: 1,
			wantErr:         false,
			wantErrMsg:      "",
		},
		{
			name: "only-null-fields",
			args: args{
				resource: &Scope{
					Scope: &iam_store.Scope{
						Name:        "only-null-fields" + id,
						Description: "updated" + id,
						CreateTime:  now,
						UpdateTime:  now,
						PublicId:    publicId,
					},
				},
				fieldMaskPaths: nil,
				setToNullPaths: []string{"Name", "Description"},
			},
			wantName:        "",
			wantDescription: "",
			wantUpdatedRows: 1,
			wantErr:         false,
			wantErrMsg:      "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			org := testOrg(t, repo, tt.name+"-orig-"+id, "orig-"+id)
			if tt.args.resource != nil {
				tt.args.resource.(*Scope).PublicId = org.PublicId
			}
			updatedResource, rowsUpdated, err := repo.update(context.Background(), tt.args.resource, 1, tt.args.fieldMaskPaths, tt.args.setToNullPaths, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(tt.wantUpdatedRows, rowsUpdated)
				assert.Contains(err.Error(), tt.wantErrMsg)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantUpdatedRows, rowsUpdated)
			err = db.TestVerifyOplog(t, rw, org.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			require.NoError(err)

			foundResource := AllocScope()
			foundResource.PublicId = updatedResource.GetPublicId()
			where := "public_id = ?"
			for _, f := range tt.args.setToNullPaths {
				where = fmt.Sprintf("%s and %s is null", where, f)
			}
			err = rw.LookupWhere(context.Background(), &foundResource, where, []any{tt.args.resource.GetPublicId()})
			require.NoError(err)
			assert.Equal(tt.args.resource.GetPublicId(), foundResource.GetPublicId())
			assert.Equal(tt.wantName, foundResource.GetName())
			assert.Equal(tt.wantDescription, foundResource.GetDescription())
			assert.NotEqual(now, foundResource.GetCreateTime())
			assert.NotEqual(now, foundResource.GetUpdateTime())
		})
	}
}
