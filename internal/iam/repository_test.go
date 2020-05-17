package iam

import (
	"context"
	"reflect"
	"testing"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
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

func Test_Repository_update(t *testing.T) {
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

		s, err := NewOrganization()
		assert.NoError(err)
		retScope, err := repo.create(context.Background(), s)
		assert.NoError(err)
		assert.NotNil(retScope)
		assert.NotEmpty(retScope.GetPublicId())
		assert.Empty(retScope.GetName())

		retScope.(*Scope).Name = "fname-" + id
		retScope, updatedRows, err := repo.update(context.Background(), retScope, []string{"Name"})
		assert.NoError(err)
		assert.NotNil(retScope)
		assert.Equal(1, updatedRows)
		assert.Equal(retScope.GetName(), "fname-"+id)

		foundScope, err := repo.LookupScope(context.Background(), s.PublicId)
		assert.NoError(err)
		assert.Equal(foundScope.GetPublicId(), retScope.GetPublicId())

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
		resource, updatedRows, err := repo.update(context.Background(), nil, nil)
		assert.NotNil(err)
		assert.Nil(resource)
		assert.Equal(0, updatedRows)
		assert.Equal(err.Error(), "error updating resource that is nil")
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
