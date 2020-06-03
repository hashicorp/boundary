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
		entryType KeyEntryType
		scopeId   string
		keyId     string
		key       []byte
		purpose   KeyPurpose
		opt       []Option
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
				entryType: OrganizationKeyEntry,
				key:       []byte("valid-" + id),
				keyId:     "valid-" + id,
				scopeId:   org.PublicId,
				opt:       []Option{WithParentKeyId("valid-" + id)},
			},
			wantErr: false,
		},
		{
			name: "bad-scope-id",
			args: args{
				entryType: OrganizationKeyEntry,
				key:       []byte("bad-scope-id-" + id),
				keyId:     "bad-scope-id-" + id,
				scopeId:   "bad-scope-id-" + id,
				opt:       []Option{WithParentKeyId("bad-scope-id-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "create: kms key entry: create: vet for write failed scope is not found for " + "bad-scope-id-" + id,
		},
		{
			name: "dup-key-id",
			args: args{
				entryType: OrganizationKeyEntry,
				key:       []byte("dup-key-id-" + id),
				keyId:     "dup-key-id-" + id,
				scopeId:   org.PublicId,
				opt:       []Option{WithParentKeyId("dup-key-id-" + id)},
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
				dup, err := NewKeyEntry(tt.args.entryType, tt.args.scopeId, tt.args.keyId, tt.args.key, tt.args.purpose)
				assert.NoError(err)
				dup, err = repo.CreateKeyEntry(context.Background(), dup, tt.args.opt...)
				assert.NoError(err)
				assert.NotNil(dup)
			}
			e, err := NewKeyEntry(tt.args.entryType, tt.args.scopeId, tt.args.keyId, tt.args.key, tt.args.purpose)
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
				entry: testKeyEntry(t, conn, org.PublicId, "valid-"+id, []byte(id), OrganizationKey),
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
					e, err := NewKeyEntry(OrganizationKeyEntry, org.PublicId, "not-found-"+id, []byte(id), OrganizationKey)
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

func TestRepository_UpdateKeyEntry(t *testing.T) {
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
		keyId          string
		key            []byte
		fieldMaskPaths []string
		opt            []Option
		ScopeId        string
		purpose        KeyPurpose
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantErrMsg     string
		wantDup        bool
	}{
		{
			name: "valid",
			args: args{
				keyId:          "valid-" + id,
				key:            []byte("valid" + id),
				fieldMaskPaths: []string{"key"},
				ScopeId:        org.PublicId,
				purpose:        OrganizationKey,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "scope-id",
			args: args{
				keyId:          "scope-id-" + id,
				key:            []byte("scope-id" + id),
				fieldMaskPaths: []string{"scopeid"},
				ScopeId:        id,
			},
			wantErr:    true,
			wantErrMsg: "update kms key entry: scope not updatable invalid parameter",
		},
		{
			name: "no-field-mask",
			args: args{
				keyId:          "no-field-mask-" + id,
				key:            []byte("no-field-mask" + id),
				fieldMaskPaths: nil,
				ScopeId:        org.PublicId,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update kms key entry: missing field masks nil parameter",
		},
		{
			name: "dup",
			args: args{
				keyId:          "dup" + id,
				key:            []byte("dup" + id),
				fieldMaskPaths: []string{"KeyId"},
				ScopeId:        org.PublicId,
			},
			wantErr:    true,
			wantDup:    true,
			wantErrMsg: "update kms key entry: key id not updatable invalid parameter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			if tt.wantDup {
				_ = testKeyEntry(t, conn, org.PublicId, tt.args.keyId+"-updated", tt.args.key, tt.args.purpose)
			}
			e := testKeyEntry(t, conn, org.PublicId, tt.args.keyId, tt.args.key, tt.args.purpose)
			updateEntry := allocKeyEntry()
			updateEntry.PublicId = e.PublicId
			updateEntry.KeyId = e.KeyId
			updateEntry.ScopeId = tt.args.ScopeId
			updateEntry.Key = append(tt.args.key, []byte("-updated")...)

			entryAfterUpdate, updatedRows, err := repo.UpdateKeyEntry(context.Background(), &updateEntry, tt.args.fieldMaskPaths, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(entryAfterUpdate)
				assert.Equal(0, updatedRows)
				switch tt.name {
				case "dup-name":
					assert.Equal(fmt.Sprintf(tt.wantErrMsg, "dup-name"+id, org.PublicId), err.Error())
				case "proj-scope-id":
					assert.Equal(fmt.Sprintf(tt.wantErrMsg, e.ScopeId), err.Error())
				default:
					assert.Equal(tt.wantErrMsg, err.Error())
				}
				err = testVerifyOplog(t, rw, tt.args.keyId, oplog.OpType_OP_TYPE_UPDATE)
				assert.Error(err)
				assert.Equal("record not found", err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			found, err := repo.LookupKeyEntry(context.Background(), e.KeyId)
			assert.NoError(err)
			assert.True(proto.Equal(entryAfterUpdate, found))

			err = testVerifyOplog(t, rw, tt.args.keyId, oplog.OpType_OP_TYPE_UPDATE)
			assert.NoError(err)
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
