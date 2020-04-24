package iam

import (
	"context"
	"reflect"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"gotest.tools/assert"
)

func TestNewDatabaseRepository(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	rw := &db.GormReadWriter{Tx: conn}
	wrapper := db.InitTestWrapper(t)
	type args struct {
		r       db.Reader
		w       db.Writer
		wrapper wrapping.Wrapper
	}
	tests := []struct {
		name          string
		args          args
		want          Repository
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
			want: &dbRepository{
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
			got, err := NewDatabaseRepository(tt.args.r, tt.args.w, tt.args.wrapper)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDatabaseRepository() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDatabaseRepository() = %v, want %v", got, tt.want)
			}
			if err != nil {
				assert.Equal(t, err.Error(), tt.wantErrString)
			}
		})
	}
}
func Test_dbRepository_Create(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-scope", func(t *testing.T) {
		rw := &db.GormReadWriter{Tx: conn}
		wrapper := db.InitTestWrapper(t)
		repo, err := NewDatabaseRepository(rw, rw, wrapper)
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		s, err := NewScope(OrganizationScope, WithFriendlyName("fname-"+id))
		retScope, err := repo.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, retScope != nil)
		assert.Check(t, retScope.GetPublicId() != "")
		assert.Equal(t, retScope.GetFriendlyName(), "fname-"+id)

		foundScope, err := NewScope(OrganizationScope)
		foundScope.PublicId = s.PublicId
		err = repo.LookupById(context.Background(), foundScope)
		assert.NilError(t, err)
		assert.Equal(t, foundScope.GetPublicId(), retScope.GetPublicId())

		foundScope.FriendlyName = "fname-" + id
		err = repo.LookupByFriendlyName(context.Background(), foundScope)
		assert.NilError(t, err)
		assert.Equal(t, foundScope.GetPublicId(), retScope.GetPublicId())

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", s.PublicId).First(&metadata).Error
		assert.NilError(t, err)

		var foundEntry oplog.Entry
		err = conn.Where("id = ?", metadata.EntryId).First(&foundEntry).Error
		assert.NilError(t, err)
	})
	t.Run("valid-user", func(t *testing.T) {
		rw := &db.GormReadWriter{Tx: conn}
		wrapper := db.InitTestWrapper(t)
		repo, err := NewDatabaseRepository(rw, rw, wrapper)

		s, err := NewScope(OrganizationScope)
		retScope, err := repo.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, retScope != nil)
		assert.Check(t, retScope.GetPublicId() != "")
		assert.Check(t, retScope.GetCreateTime() != nil)
		assert.Check(t, retScope.GetUpdateTime() != nil)

		user, err := NewUser(retScope.(*Scope))
		assert.NilError(t, err)
		retUser, err := repo.Create(context.Background(), user)
		assert.NilError(t, err)
		assert.Check(t, retUser != nil)
		assert.Check(t, retUser.GetPublicId() != "")
		assert.Equal(t, retUser.(*User).PrimaryScopeId, retScope.(*Scope).Id)

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", user.PublicId).First(&metadata).Error
		assert.NilError(t, err)

		var foundEntry oplog.Entry
		err = conn.Where("id = ?", metadata.GetEntryId()).First(&foundEntry).Error
		assert.NilError(t, err)
	})
	t.Run("nil-resource", func(t *testing.T) {
		rw := &db.GormReadWriter{Tx: conn}
		wrapper := db.InitTestWrapper(t)
		repo, err := NewDatabaseRepository(rw, rw, wrapper)
		ret, err := repo.Create(context.Background(), nil)
		assert.Check(t, err != nil)
		assert.Check(t, ret == nil)
		assert.Equal(t, err.Error(), "error creating resource that is nil")
	})
}

func Test_dbRepository_Update(t *testing.T) {
	db.StartTest()
	t.Parallel()
	cleanup, url := db.SetupTest(t, "../db/migrations/postgres")
	defer cleanup()
	defer db.CompleteTest() // must come after the "defer cleanup()"
	conn, err := db.TestConnection(url)
	assert.NilError(t, err)
	defer conn.Close()

	t.Run("valid-scope", func(t *testing.T) {
		rw := &db.GormReadWriter{Tx: conn}
		wrapper := db.InitTestWrapper(t)
		repo, err := NewDatabaseRepository(rw, rw, wrapper)
		id, err := uuid.GenerateUUID()
		assert.NilError(t, err)

		s, err := NewScope(OrganizationScope)
		retScope, err := repo.Create(context.Background(), s)
		assert.NilError(t, err)
		assert.Check(t, retScope != nil)
		assert.Check(t, retScope.GetPublicId() != "")
		assert.Equal(t, retScope.GetFriendlyName(), "")

		retScope.(*Scope).FriendlyName = "fname-" + id
		retScope, err = repo.Update(context.Background(), retScope, []string{"FriendlyName"})
		assert.NilError(t, err)
		assert.Check(t, retScope != nil)
		assert.Equal(t, retScope.GetFriendlyName(), "fname-"+id)

		foundScope, err := NewScope(OrganizationScope)
		foundScope.FriendlyName = "fname-" + id
		err = repo.LookupByFriendlyName(context.Background(), foundScope)
		assert.NilError(t, err)
		assert.Equal(t, foundScope.GetPublicId(), retScope.GetPublicId())

		var metadata store.Metadata
		err = conn.Where("key = ? and value = ?", "resource-public-id", s.PublicId).First(&metadata).Error
		assert.NilError(t, err)

		var foundEntry oplog.Entry
		err = conn.Where("id = ?", metadata.EntryId).First(&foundEntry).Error
		assert.NilError(t, err)
	})
	t.Run("nil-resource", func(t *testing.T) {
		rw := &db.GormReadWriter{Tx: conn}
		wrapper := db.InitTestWrapper(t)
		repo, err := NewDatabaseRepository(rw, rw, wrapper)
		ret, err := repo.Update(context.Background(), nil, nil)
		assert.Check(t, err != nil)
		assert.Check(t, ret == nil)
		assert.Equal(t, err.Error(), "error updating resource that is nil")
	})
}
