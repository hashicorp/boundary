// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/db_test"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDb_Create_OnConflict(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	oplogWrapper := db.TestOplogWrapper(t, conn)
	rw := db.New(conn)
	db.TestCreateTables(t, conn)

	createInitialUser := func() *db_test.TestUser {
		// create initial user for on conflict tests
		id, err := db.NewPublicId(ctx, "test-user")
		require.NoError(t, err)
		initialUser, err := db_test.NewTestUser()
		require.NoError(t, err)
		ts := &timestamp.Timestamp{Timestamp: timestamppb.Now()}
		initialUser.CreateTime = ts
		initialUser.UpdateTime = ts
		initialUser.Name = "foo-" + id
		err = rw.Create(ctx, initialUser)
		require.NoError(t, err)
		assert.NotEmpty(t, initialUser.Id)
		return initialUser
	}
	tests := []struct {
		name           string
		onConflict     db.OnConflict
		additionalOpts []db.Option
		wantUpdate     bool
		wantEmail      string
		wantOplog      bool
	}{
		{
			name: "set-columns",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.SetColumns([]string{"name"}),
			},
			wantUpdate: true,
			wantOplog:  true,
		},
		{
			name: "set-column-values",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.SetColumnValues(map[string]any{
					"name":         db.Expr("md5(?)", "alice eve smith"),
					"email":        "alice@gmail.com",
					"phone_number": db.Expr("NULL"),
				}),
			},
			wantUpdate: true,
			wantEmail:  "alice@gmail.com",
			wantOplog:  true,
		},
		{
			name: "both-set-columns-and-set-column-values",
			onConflict: func() db.OnConflict {
				onConflict := db.OnConflict{
					Target: db.Columns{"public_id"},
				}
				cv := db.SetColumns([]string{"name"})
				cv = append(cv,
					db.SetColumnValues(map[string]any{
						"email":        "alice@gmail.com",
						"phone_number": db.Expr("NULL"),
					})...)
				onConflict.Action = cv
				return onConflict
			}(),
			wantUpdate: true,
			wantEmail:  "alice@gmail.com",
			wantOplog:  true,
		},
		{
			name: "update-all",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.UpdateAll(true),
			},
			wantUpdate: true,
			wantOplog:  true,
		},
		{
			name: "do-nothing",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.DoNothing(true),
			},
			wantOplog: false,
		},
		{
			name: "on-constraint",
			onConflict: db.OnConflict{
				Target: db.Constraint("db_test_user_public_id_key"),
				Action: db.SetColumns([]string{"name"}),
			},
			wantUpdate: true,
			wantOplog:  true,
		},
		{
			name: "set-columns-with-where-success",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithWhere("db_test_user.version = ?", 1)},
			wantUpdate:     true,
			wantOplog:      true,
		},
		{
			name: "set-columns-with-where-fail",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithWhere("db_test_user.version = ?", 100000000000)},
			wantUpdate:     false,
			wantOplog:      false,
		},
		{
			name: "set-columns-with-version-success",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithVersion(func() *uint32 { i := uint32(1); return &i }())},
			wantUpdate:     true,
			wantOplog:      true,
		},
		{
			name: "set-columns-with-version-fail",
			onConflict: db.OnConflict{
				Target: db.Columns{"public_id"},
				Action: db.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithWhere("db_test_user.version = ?", 100000000000)},
			wantUpdate:     false,
			wantOplog:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			initialUser := createInitialUser()
			conflictUser, err := db_test.NewTestUser()
			require.NoError(err)
			userNameId, err := db.NewPublicId(ctx, "test-user-name")
			require.NoError(err)
			conflictUser.PublicId = initialUser.PublicId
			conflictUser.Name = userNameId
			md := oplog.Metadata{
				"resource-public-id": []string{conflictUser.PublicId},
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
			}
			var rowsAffected int64
			opts := []db.Option{db.WithOnConflict(&tt.onConflict), db.WithOplog(oplogWrapper, md), db.WithReturnRowsAffected(&rowsAffected)}
			if tt.additionalOpts != nil {
				opts = append(opts, tt.additionalOpts...)
			}
			err = rw.Create(ctx, conflictUser, opts...)
			require.NoError(err)
			if tt.wantOplog {
				err = db.TestVerifyOplog(t, rw, conflictUser.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
				assert.NoError(err)
			}
			foundUser, err := db_test.NewTestUser()
			require.NoError(err)
			foundUser.PublicId = conflictUser.PublicId
			err = rw.LookupByPublicId(context.Background(), foundUser)
			require.NoError(err)
			t.Log(foundUser)
			if tt.wantUpdate {
				assert.Equal(int64(1), rowsAffected)
				assert.Equal(conflictUser.Id, foundUser.Id)
				assert.Equal(conflictUser.Name, foundUser.Name)
				if tt.wantEmail != "" {
					assert.Equal(tt.wantEmail, foundUser.Email)
				}
			} else {
				assert.Equal(int64(0), rowsAffected)
				assert.NotEqual(conflictUser.Id, foundUser.Id)
				assert.NotEqual(conflictUser.Name, foundUser.Name)
			}
		})
	}
	t.Run("CreateItems", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		initialUser := createInitialUser()
		conflictUser, err := db_test.NewTestUser()
		require.NoError(err)
		userNameId, err := db.NewPublicId(ctx, "test-user-name")
		require.NoError(err)
		conflictUser.PublicId = initialUser.PublicId
		conflictUser.Name = userNameId
		md := oplog.Metadata{
			"resource-public-id": []string{conflictUser.PublicId},
			"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		}
		onConflict := db.OnConflict{
			Target: db.Constraint("db_test_user_public_id_key"),
			Action: db.SetColumns([]string{"name"}),
		}
		users := []*db_test.TestUser{}
		users = append(users, conflictUser)
		var rowsAffected int64
		err = rw.CreateItems(ctx, users, db.WithOnConflict(&onConflict), db.WithOplog(oplogWrapper, md), db.WithReturnRowsAffected(&rowsAffected))
		require.NoError(err)
		foundUser, err := db_test.NewTestUser()
		require.NoError(err)
		foundUser.PublicId = conflictUser.PublicId
		err = rw.LookupByPublicId(context.Background(), foundUser)
		require.NoError(err)

		assert.Equal(int64(1), rowsAffected)
		assert.Equal(conflictUser.Id, foundUser.Id)
		assert.Equal(conflictUser.Name, foundUser.Name)
	})
}

func TestRW_IsTx(t *testing.T) {
	t.Parallel()
	testCtx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	assert, require := assert.New(t), require.New(t)

	assert.False(rw.IsTx(testCtx))

	_, err := rw.DoTx(context.Background(), 10, db.ExpBackoff{},
		func(_ db.Reader, txWriter db.Writer) error {
			assert.True(txWriter.IsTx(testCtx))
			return nil
		})
	require.NoError(err)
}
