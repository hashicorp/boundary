package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/db_test"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-dbw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDb_Create_OnConflict(t *testing.T) {
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	db.TestCreateTables(t, conn)

	createInitialUser := func() *db_test.TestUser {
		// create initial user for on conflict tests
		id, err := db.NewPublicId("test-user")
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
		onConflict     dbw.OnConflict
		additionalOpts []db.Option
		wantUpdate     bool
		wantEmail      string
		wantOplog      bool
	}{
		{
			name: "set-columns",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.SetColumns([]string{"name"}),
			},
			wantUpdate: true,
			wantOplog:  true,
		},
		{
			name: "set-column-values",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.SetColumnValues(map[string]interface{}{
					"name":         dbw.Expr("md5(?)", "alice eve smith"),
					"email":        "alice@gmail.com",
					"phone_number": dbw.Expr("NULL"),
				}),
			},
			wantUpdate: true,
			wantEmail:  "alice@gmail.com",
			wantOplog:  true,
		},
		{
			name: "both-set-columns-and-set-column-values",
			onConflict: func() dbw.OnConflict {
				onConflict := dbw.OnConflict{
					Target: dbw.Columns{"public_id"},
				}
				cv := dbw.SetColumns([]string{"name"})
				cv = append(cv,
					dbw.SetColumnValues(map[string]interface{}{
						"email":        "alice@gmail.com",
						"phone_number": dbw.Expr("NULL"),
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
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.UpdateAll(true),
			},
			wantUpdate: true,
			wantOplog:  true,
		},
		{
			name: "do-nothing",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.DoNothing(true),
			},
			wantOplog: false,
		},
		{
			name: "on-constraint",
			onConflict: dbw.OnConflict{
				Target: dbw.Constraint("db_test_user_public_id_key"),
				Action: dbw.SetColumns([]string{"name"}),
			},
			wantUpdate: true,
			wantOplog:  true,
		},
		{
			name: "set-columns-with-where-success",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithWhere("db_test_user.version = ?", 1)},
			wantUpdate:     true,
			wantOplog:      true,
		},
		{
			name: "set-columns-with-where-fail",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithWhere("db_test_user.version = ?", 100000000000)},
			wantUpdate:     false,
			wantOplog:      false,
		},
		{
			name: "set-columns-with-version-success",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.SetColumns([]string{"name"}),
			},
			additionalOpts: []db.Option{db.WithVersion(func() *uint32 { i := uint32(1); return &i }())},
			wantUpdate:     true,
			wantOplog:      true,
		},
		{
			name: "set-columns-with-version-fail",
			onConflict: dbw.OnConflict{
				Target: dbw.Columns{"public_id"},
				Action: dbw.SetColumns([]string{"name"}),
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
			userNameId, err := db.NewPublicId("test-user-name")
			require.NoError(err)
			conflictUser.PublicId = initialUser.PublicId
			conflictUser.Name = userNameId
			md := oplog.Metadata{
				"resource-public-id": []string{conflictUser.PublicId},
				"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
			}
			var rowsAffected int64
			opts := []db.Option{db.WithOnConflict(&tt.onConflict), db.WithOplog(wrapper, md), db.WithReturnRowsAffected(&rowsAffected)}
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
		userNameId, err := db.NewPublicId("test-user-name")
		require.NoError(err)
		conflictUser.PublicId = initialUser.PublicId
		conflictUser.Name = userNameId
		md := oplog.Metadata{
			"resource-public-id": []string{conflictUser.PublicId},
			"op-type":            []string{oplog.OpType_OP_TYPE_CREATE.String()},
		}
		onConflict := dbw.OnConflict{
			Target: dbw.Constraint("db_test_user_public_id_key"),
			Action: dbw.SetColumns([]string{"name"}),
		}
		users := []interface{}{}
		users = append(users, conflictUser)
		var rowsAffected int64
		err = rw.CreateItems(ctx, users, db.WithOnConflict(&onConflict), db.WithOplog(wrapper, md), db.WithReturnRowsAffected(&rowsAffected))
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
