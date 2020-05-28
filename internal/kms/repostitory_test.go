package kms

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/oplog"
	"github.com/hashicorp/watchtower/internal/oplog/store"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestRepository_CreateKeyEntry(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	org := testOrg(t, conn)
	id := testId(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)

	type args struct {
		organizationPublicId string
		keyId                string
		key                  []byte
		opt                  []Option
	}
	tests := []struct {
		name       string
		args       args
		wantDup    bool
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "valid",
			args: args{
				key:                  []byte("valid-" + id),
				keyId:                "valid-" + id,
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("valid-" + id)},
			},
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				key:                  []byte("bad-scope-id-" + id),
				keyId:                "bad-scope-id-" + id,
				organizationPublicId: "bad-scope-id-" + id,
				opt:                  []Option{WithParentKeyId("bad-scope-id-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "create: kms key entry: create: vet for write failed scope is not found for " + "bad-scope-id-" + id,
		},
		{
			name: "dup-key-id",
			args: args{
				key:                  []byte("dup-key-id-" + id),
				keyId:                "dup-key-id-" + id,
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("dup-key-id-" + id)},
			},
			wantDup:    true,
			wantErr:    true,
			wantErrMsg: fmt.Sprintf("create: kms key entry: key entry dup-key-id-%s already exists in organization %s", id, org.PublicId),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			if tt.wantDup {
				dup, err := NewKeyEntry(tt.args.organizationPublicId, tt.args.keyId, tt.args.key)
				assert.NoError(err)
				dup, err = repo.CreateKeyEntry(context.Background(), dup, tt.args.opt...)
				assert.NoError(err)
				assert.NotNil(dup)
			}
			e, err := NewKeyEntry(tt.args.organizationPublicId, tt.args.keyId, tt.args.key)
			keyId := e.KeyId
			assert.NoError(err)
			e, err = repo.CreateKeyEntry(context.Background(), e, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(e)
				if tt.wantDup {
					return
				}
				err = testVerifyOplog(t, rw, keyId, oplog.OpType_OP_TYPE_CREATE)
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			foundUser, err := repo.LookupKeyEntry(context.Background(), keyId)
			assert.NoError(err)
			assert.True(proto.Equal(foundUser, e))

			err = testVerifyOplog(t, rw, keyId, oplog.OpType_OP_TYPE_CREATE)
			assert.NoError(err)
		})
	}
}

func TestRepository_DeleteKeyEntry(t *testing.T) {
	t.Parallel()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	org := testOrg(t, conn)
	id := testId(t)
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)

	type args struct {
		entry *KeyEntry
		opt   []Option
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
				entry: testKeyEntry(t, conn, org.PublicId, "valid-"+id, []byte(id)),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-key-id",
			args: args{
				entry: func() *KeyEntry {
					e := allocKeyEntry()
					return &e
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete kms key entry: missing key id nil parameter",
		},
		{
			name: "not-found",
			args: args{
				entry: func() *KeyEntry {
					e, err := NewKeyEntry(org.PublicId, "not-found-"+id, []byte(id))
					assert.NoError(t, err)
					return e
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         false,
			wantErrMsg:      "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteKeyEntry(context.Background(), tt.args.entry.KeyId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				err = testVerifyOplog(t, rw, tt.args.entry.KeyId, oplog.OpType_OP_TYPE_DELETE)
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundUser, err := repo.LookupKeyEntry(context.Background(), tt.args.entry.KeyId)
			assert.Error(err)
			assert.Nil(foundUser)
			assert.True(errors.Is(err, db.ErrRecordNotFound))
			err = testVerifyOplog(t, rw, tt.args.entry.KeyId, oplog.OpType_OP_TYPE_DELETE)
			assert.Error(err)
		})
	}
}
func testVerifyOplog(t *testing.T, r db.Reader, keyId string, withOperation oplog.OpType) error {
	// intentionally not a t.Helper()

	// sql where clauses
	const (
		whereBase = `
      key = 'resource-key-id'
and value = ?
`
		whereOptype = `
and entry_id in (
  select entry_id
    from oplog_metadata
	 where key = 'op-type'
     and value = ?
)
`
		whereCreateNotBefore = `
and create_time > NOW()::timestamp - (interval '1 second' * 10)
`
	)

	where := whereBase
	whereArgs := []interface{}{
		keyId,
	}

	if withOperation != oplog.OpType_OP_TYPE_UNSPECIFIED {
		where = where + whereOptype
		whereArgs = append(whereArgs, withOperation.String())
	}

	var metadata store.Metadata
	if err := r.LookupWhere(context.Background(), &metadata, where, whereArgs...); err != nil {
		return err
	}

	var foundEntry oplog.Entry
	if err := r.LookupWhere(context.Background(), &foundEntry, "id = ?", metadata.EntryId); err != nil {
		return err
	}
	return nil
}
