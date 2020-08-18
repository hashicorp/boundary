package iam

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
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
			wantErrString: "error creating db repository with nil kms",
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
			wantErrString: "error creating db repository with nil writer",
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
			wantErrString: "error creating db repository with nil reader",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.kms)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(err.Error(), tt.wantErrString)
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}
func Test_Repository_create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	repo := TestRepo(t, conn, wrapper)
	t.Run("valid-scope", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		id := testId(t)

		s, err := NewOrg(WithName("fname-" + id))
		assert.NoError(err)
		s.PublicId, err = newScopeId(scope.Org)
		require.NoError(err)
		retScope, err := repo.create(context.Background(), s)
		require.NoError(err)
		require.NotNil(retScope)
		assert.NotEmpty(retScope.GetPublicId())
		assert.Equal(retScope.GetName(), "fname-"+id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		require.NoError(err)
		assert.True(proto.Equal(foundScope, retScope.(*Scope)))

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", s.PublicId).First(&metadata).Error
		require.NoError(err)

		var foundEntry oplog.Entry
		err = conn.Where("id = ?", metadata.EntryId).First(&foundEntry).Error
		assert.NoError(err)
	})
	t.Run("nil-resource", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		resource, err := repo.create(context.Background(), nil)
		require.Error(err)
		assert.Nil(resource)
		assert.Equal(err.Error(), "error creating resource that is nil")
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
	require.NoError(t, conn.Where("1=1").Delete(kms.AllocRootKey()).Error)
	t.Run("nil-resource", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		deletedRows, err := repo.delete(context.Background(), nil, nil)
		require.Error(err)
		assert.Equal(0, deletedRows)
		assert.Equal(err.Error(), "error deleting resource that is nil")
	})
}

func TestRepository_update(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	now := &timestamp.Timestamp{Timestamp: ptypes.TimestampNow()}
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
			wantErrMsg:      "error updating resource that is nil",
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
			wantErrMsg:      "update: getting update fields failed: fieldMashPaths and setToNullPaths cannot intersect",
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
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantUpdatedRows, rowsUpdated)
			err = db.TestVerifyOplog(t, rw, org.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			require.NoError(err)

			foundResource := allocScope()
			foundResource.PublicId = updatedResource.GetPublicId()
			where := "public_id = ?"
			for _, f := range tt.args.setToNullPaths {
				where = fmt.Sprintf("%s and %s is null", where, f)
			}
			err = rw.LookupWhere(context.Background(), &foundResource, where, tt.args.resource.GetPublicId())
			require.NoError(err)
			assert.Equal(tt.args.resource.GetPublicId(), foundResource.GetPublicId())
			assert.Equal(tt.wantName, foundResource.GetName())
			assert.Equal(tt.wantDescription, foundResource.GetDescription())
			assert.NotEqual(now, foundResource.GetCreateTime())
			assert.NotEqual(now, foundResource.GetUpdateTime())
		})
	}
}
