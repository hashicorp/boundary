// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package purge

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPurgeTables(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	db, err := conn.SqlDB(ctx)
	if err != nil {
		t.Errorf("error getting db connection %s", err)
	}

	rows, err := db.Query("select tablename from deletion_table")
	if err != nil {
		t.Errorf("unable to query for deletion tables %s", err)
	}
	defer rows.Close()

	for rows.Next() {
		var table string
		err = rows.Scan(&table)
		if err != nil {
			t.Errorf("unable to scan rows for deletion tables %s", err)
		}
		_, err = db.Exec(fmt.Sprintf("insert into %s (public_id, delete_time) values ('p1234567890', $1)", table), time.Now())
		if err != nil {
			t.Errorf("error updating %s %s", table, err)
		}
		_, err = db.Exec(fmt.Sprintf("insert into %s (public_id, delete_time) values ('p9876543210', $1)", table), time.Now().AddDate(0, -2, 0))
		if err != nil {
			t.Errorf("error updating %s %s", table, err)
		}

		query := fmt.Sprintf("delete from %s where delete_time < now() - interval '30 days'", table)
		sJob := purgeJob{
			w:     rw,
			table: table,
			query: query,
		}

		err = sJob.Run(ctx, 0)
		require.NoError(t, err)

		var count int
		err = db.QueryRowContext(ctx, fmt.Sprintf("select count(public_id) from %s", table)).Scan(&count)
		if err != nil {
			t.Errorf("error checking %s table %s", table, err)
		}
		require.Equal(t, 1, count)
	}
	require.NoError(t, rows.Err())
}

func TestNewPurgeJob(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	type args struct {
		w     db.Writer
		table string
	}

	tests := []struct {
		name       string
		args       args
		wantIsErr  errors.Code
		wantErrMsg string
	}{
		{
			name: "valid",
			args: args{
				w:     rw,
				table: "valid-table",
			},
		},
		{
			name: "nil-writer",
			args: args{
				w:     nil,
				table: "valid-table",
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "purgeJob.newPurgeJob: missing db.Writer: parameter violation: error #100",
		},
		{
			name: "no table",
			args: args{
				w:     rw,
				table: "",
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "purgeJob.newPurgeJob: missing table: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newPurgeJob(ctx, tt.args.w, tt.args.table)
			if tt.wantIsErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantIsErr), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			require.NotNil(got)
		})
	}
}
