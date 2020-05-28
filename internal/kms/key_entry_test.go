package kms

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/kms/store"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestNewKeyEntry(t *testing.T) {
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
	assert := assert.New(t)
	org := testOrg(t, conn)

	id := testId(t)

	type args struct {
		organizationPublicId string
		keyId                string
		key                  []byte
		opt                  []Option
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		wantErrMsg string
		want       *KeyEntry
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
			want: &KeyEntry{
				KeyEntry: &store.KeyEntry{
					Key:         []byte("valid-" + id),
					KeyId:       "valid-" + id,
					ScopeId:     org.PublicId,
					ParentKeyId: "valid-" + id,
				},
			},
		},
		{
			name: "valid-no-parent",
			args: args{
				key:                  []byte("valid-no-parent-" + id),
				keyId:                "valid-no-parent-" + id,
				organizationPublicId: org.PublicId,
			},
			wantErr: false,
			want: &KeyEntry{
				KeyEntry: &store.KeyEntry{
					Key:     []byte("valid-no-parent-" + id),
					KeyId:   "valid-no-parent-" + id,
					ScopeId: org.PublicId,
				},
			},
		},
		{
			name: "nil-key",
			args: args{
				key:                  nil,
				keyId:                "nil-key-" + id,
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("nil-key-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "new key entry: missing key nil parameter",
			want:       nil,
		},
		{
			name: "no-key-id",
			args: args{
				key:                  []byte("no-key-id-" + id),
				keyId:                "",
				organizationPublicId: org.PublicId,
				opt:                  []Option{WithParentKeyId("no-key-id-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "new key entry: missing key id nil parameter",
			want:       nil,
		},
		{
			name: "no-org-id",
			args: args{
				key:                  []byte("no-org-id-" + id),
				keyId:                "no-org-id-" + id,
				organizationPublicId: "",
				opt:                  []Option{WithParentKeyId("no-org-id-" + id)},
			},
			wantErr:    true,
			wantErrMsg: "new key entry: missing organization id nil parameter",
			want:       nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewKeyEntry(tt.args.organizationPublicId, tt.args.keyId, tt.args.key, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.want.KeyEntry, got.KeyEntry)
		})
	}
}

func Test_KeyEntryCreate(t *testing.T) {
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
	assert := assert.New(t)
	org := testOrg(t, conn)

	id := testId(t)

	t.Run("valid", func(t *testing.T) {
		w := db.New(conn)
		entry, err := NewKeyEntry(org.PublicId, "valid-"+id, []byte(id))
		assert.NoError(err)
		err = w.Create(context.Background(), entry)
		assert.NoError(err)

		found := allocKeyEntry()
		err = w.LookupWhere(context.Background(), &found, "key_id = ?", entry.KeyId)
		assert.NoError(err)
		assert.Equal(entry, &found)

		subKey, err := NewKeyEntry(org.PublicId, "valid-sub-"+id, []byte(id), WithParentKeyId(entry.KeyId))
		assert.NoError(err)
		err = w.Create(context.Background(), subKey)
		assert.NoError(err)
		found = allocKeyEntry()
		err = w.LookupWhere(context.Background(), &found, "key_id = ?", subKey.KeyId)
		assert.NoError(err)
		assert.Equal(subKey, &found)
	})
	t.Run("dup", func(t *testing.T) {
		w := db.New(conn)
		entry, err := NewKeyEntry(org.PublicId, "dup-"+id, []byte(id))
		assert.NoError(err)
		err = w.Create(context.Background(), entry)
		assert.NoError(err)

		found := allocKeyEntry()
		err = w.LookupWhere(context.Background(), &found, "key_id = ?", entry.KeyId)
		assert.NoError(err)
		assert.Equal(entry, &found)

		entryWithParent, err := NewKeyEntry(org.PublicId, "dup-"+id, []byte(id))
		assert.NoError(err)
		err = w.Create(context.Background(), entryWithParent)
		assert.Error(err)
	})
	t.Run("bad-org", func(t *testing.T) {
		w := db.New(conn)
		entry, err := NewKeyEntry(id, "bad-org-"+id, []byte(id))
		assert.NoError(err)
		err = w.Create(context.Background(), entry)
		assert.Error(err)

		found := allocKeyEntry()
		err = w.LookupWhere(context.Background(), &found, "key_id = ?", entry.KeyId)
		assert.Error(err)
	})

}

func Test_KeyEntryDelete(t *testing.T) {
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

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	id := testId(t)
	org := testOrg(t, conn)

	tests := []struct {
		name            string
		keyEntry        *KeyEntry
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			keyEntry:        testKeyEntry(t, conn, org.PublicId, "valid-"+id, []byte("valid-"+id)),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-id",
			keyEntry:        func() *KeyEntry { e := allocKeyEntry(); e.KeyId = id; return &e }(),
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deleteEntry := allocKeyEntry()
			deleteEntry.KeyId = tt.keyEntry.KeyId
			deletedRows, err := rw.Delete(context.Background(), &deleteEntry)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found, err := repo.LookupKeyEntry(context.Background(), tt.keyEntry.KeyId)
			assert.True(errors.Is(err, db.ErrRecordNotFound))
			assert.Nil(found)
		})
	}
}

func Test_KeyEntryUpdate(t *testing.T) {
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

	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	repo, err := NewRepository(rw, rw, wrapper)
	assert.NoError(t, err)
	id := testId(t)
	org := testOrg(t, conn)

	type args struct {
		keyId          string
		key            []byte
		parentId       string
		fieldMaskPaths []string
		ScopeId        string
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
				key:            []byte("valid-" + id),
				parentId:       "",
				fieldMaskPaths: []string{"key"},
				ScopeId:        org.PublicId,
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "bad-scope",
			args: args{
				keyId:          "bad-scope-" + id,
				key:            []byte("bad-scope-" + id),
				parentId:       "",
				fieldMaskPaths: []string{"ScopeId"},
				ScopeId:        "bad-scope-" + id,
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantErrMsg:     "update: vet for write failed not allowed to change a key entry's scope",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			e := testKeyEntry(t, conn, org.PublicId, tt.args.keyId, tt.args.key)

			updateEntry := allocKeyEntry()
			updateEntry.KeyId = e.KeyId
			updateEntry.Key = append(tt.args.key, []byte("-updated")...)
			updateEntry.ScopeId = tt.args.ScopeId

			// TODO (jimlambrt 5/2020) Need to add nullFields parameter when
			// support is merged to master
			updatedRows, err := rw.Update(context.Background(), &updateEntry, tt.args.fieldMaskPaths)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, updatedRows)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			found, err := repo.LookupKeyEntry(context.Background(), e.KeyId)
			assert.NoError(err)
			assert.True(proto.Equal(updateEntry, found))
		})
	}
}

func Test_KeyEntryGetScope(t *testing.T) {
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

	t.Run("valid-scope", func(t *testing.T) {
		assert := assert.New(t)
		rw := db.New(conn)
		id := testId(t)

		e := testKeyEntry(t, conn, org.PublicId, id, []byte(id))
		s, err := e.GetScope(context.Background(), rw)
		assert.NoError(err)
		assert.Equal(e.ScopeId, s.PublicId)
	})
	t.Run("valid-no-scopeId-in-entry", func(t *testing.T) {
		assert := assert.New(t)
		rw := db.New(conn)
		id := testId(t)

		e := testKeyEntry(t, conn, org.PublicId, id, []byte(id))
		e.ScopeId = ""
		s, err := e.GetScope(context.Background(), rw)
		assert.NoError(err)
		assert.Equal(e.ScopeId, s.PublicId)
	})

}

func Test_KeyEntryClone(t *testing.T) {
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

	t.Run("valid", func(t *testing.T) {
		assert := assert.New(t)
		id := testId(t)
		e := testKeyEntry(t, conn, org.PublicId, id, []byte(id))

		cp := e.Clone()
		assert.True(proto.Equal(cp.KeyEntry, e.KeyEntry))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert := assert.New(t)
		id := testId(t)
		e := testKeyEntry(t, conn, org.PublicId, id, []byte(id))
		e2 := testKeyEntry(t, conn, org.PublicId, "second-"+id, []byte(id))

		cp := e.Clone()
		assert.True(!proto.Equal(cp.KeyEntry, e2.KeyEntry))
	})
}
