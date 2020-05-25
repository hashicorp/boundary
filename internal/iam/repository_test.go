package iam

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	iam_store "github.com/hashicorp/watchtower/internal/iam/store"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
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
				r:       rw,
				w:       rw,
				wrapper: wrapper,
			},
			want: &Repository{
				reader:  rw,
				writer:  rw,
				wrapper: wrapper,
			},
			wantErr: false,
		},
		{
			name: "nil-wrapper",
			args: args{
				r:       rw,
				w:       rw,
				wrapper: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil wrapper",
		},
		{
			name: "nil-writer",
			args: args{
				r:       rw,
				w:       nil,
				wrapper: wrapper,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil writer",
		},
		{
			name: "nil-reader",
			args: args{
				r:       nil,
				w:       rw,
				wrapper: wrapper,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil reader",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRepository(tt.args.r, tt.args.w, tt.args.wrapper)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRepository() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRepository() = %v, want %v", got, tt.want)
			}
			if err != nil {
				assert.Equal(err.Error(), tt.wantErrString)
			}
		})
	}
}
func Test_Repository_create(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-scope", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		id, err := uuid.GenerateUUID()
		assert.NoError(err)

		s, err := NewOrganization(WithName("fname-" + id))
		assert.NoError(err)
		retScope, err := repo.create(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(retScope)
		assert.NotEmpty(retScope.GetPublicId())
		assert.Equal(retScope.GetName(), "fname-"+id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.True(proto.Equal(foundScope, retScope.(*Scope)))

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", s.PublicId).First(&metadata).Error
		assert.NoError(err)

		var foundEntry oplog.Entry
		err = conn.Where("id = ?", metadata.EntryId).First(&foundEntry).Error
		assert.NoError(err)
	})
	t.Run("nil-resource", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		resource, err := repo.create(context.Background(), nil)
		assert.NotNil(err)
		assert.Nil(resource)
		assert.Equal(err.Error(), "error creating resource that is nil")
	})
}

func Test_Repository_delete(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	assert := assert.New(t)
	defer conn.Close()

	t.Run("valid-org", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)

		s, err := NewOrganization()
		assert.NoError(err)
		retScope, err := repo.create(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(retScope)
		assert.NotEmpty(retScope.GetPublicId())
		assert.Equal(retScope.GetName(), "")

		rowsDeleted, err := repo.delete(context.Background(), s)
		assert.NoError(err)
		assert.Equal(1, rowsDeleted)

		err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(5*time.Second))
		assert.NoError(err)
	})
	t.Run("nil-resource", func(t *testing.T) {
		rw := db.New(conn)
		wrapper := db.TestWrapper(t)
		repo, err := NewRepository(rw, rw, wrapper)
		assert.NoError(err)
		deletedRows, err := repo.delete(context.Background(), nil, nil)
		assert.NotNil(err)
		assert.Equal(0, deletedRows)
		assert.Equal(err.Error(), "error deleting resource that is nil")
	})
}

func TestRepository_update(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	now := &iam_store.Timestamp{Timestamp: ptypes.TimestampNow()}
	id := testId(t)
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	}()
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
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
			assert := assert.New(t)
			r := &Repository{
				reader:  rw,
				writer:  rw,
				wrapper: wrapper,
			}
			org := testOrg(t, conn, tt.name+"-orig-"+id, "orig-"+id)
			if tt.args.resource != nil {
				tt.args.resource.(*Scope).PublicId = org.PublicId
			}
			updatedResource, rowsUpdated, err := r.update(context.Background(), tt.args.resource, tt.args.fieldMaskPaths, tt.args.setToNullPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantUpdatedRows, rowsUpdated)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantUpdatedRows, rowsUpdated)
			err = db.TestVerifyOplog(t, rw, org.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			foundResource := allocScope()
			foundResource.PublicId = updatedResource.GetPublicId()
			where := "public_id = ?"
			for _, f := range tt.args.setToNullPaths {
				where = fmt.Sprintf("%s and %s is null", where, f)
			}
			err = rw.LookupWhere(context.Background(), &foundResource, where, tt.args.resource.GetPublicId())
			assert.NoError(err)
			assert.Equal(tt.args.resource.GetPublicId(), foundResource.GetPublicId())
			assert.Equal(tt.wantName, foundResource.GetName())
			assert.Equal(tt.wantDescription, foundResource.GetDescription())
			assert.NotEqual(now, foundResource.GetCreateTime())
			assert.NotEqual(now, foundResource.GetUpdateTime())
		})
	}
}
