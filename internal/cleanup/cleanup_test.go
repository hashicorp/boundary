// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cleanup

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrototypeInsertDeleteAndClear(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := session.TestDefaultSession(t, conn, wrapper, iamRepo)
	rw := db.New(conn)

	db, err := conn.SqlDB(ctx)
	if err != nil {
		t.Errorf("error getting db connection %s", err)
	}

	_, err = db.Exec(fmt.Sprintf(`delete from target where public_id = '%s'`, session.TargetId))
	if err != nil {
		t.Errorf("error deleting from target %s", err)
	}

	// make sure that the trigger works
	rows, err := db.Query("select count(public_id) from target_deleted")
	if err != nil {
		t.Errorf("error checking target_deleted table %s", err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		err = rw.ScanRows(ctx, rows, &count)
		if err != nil {
			t.Error("unable to scan rows for census sessions pending count")
		}
	}
	require.Equal(t, 1, count)

	sJob := cleanupJob{
		r: rw,
		w: rw,
	}

	err = sJob.Run(ctx)
	require.NoError(t, err)

	// make sure that the job doesn't clean up
	rows, err = db.Query("select count(public_id) from target_deleted")
	if err != nil {
		t.Errorf("error checking target_deleted table %s", err)
	}
	defer rows.Close()
	count = 0
	for rows.Next() {
		err = rw.ScanRows(ctx, rows, &count)
		if err != nil {
			t.Error("unable to scan rows for census sessions pending count")
		}
	}
	require.Equal(t, 1, count)

	_, err = db.Exec(`update target_deleted set delete_time = '2023-05-18';`)
	if err != nil {
		t.Errorf("error updating target_deleted %s", err)
	}

	err = sJob.Run(ctx)
	require.NoError(t, err)

	// make sure that the job did clean up
	rows, err = db.Query("select count(public_id) from target_deleted")
	if err != nil {
		t.Errorf("error checking target_deleted table %s", err)
	}
	defer rows.Close()
	count = 0
	for rows.Next() {
		err = rw.ScanRows(ctx, rows, &count)
		if err != nil {
			t.Error("unable to scan rows for census sessions pending count")
		}
	}
	require.Equal(t, 0, count)

}

func TestNewCleanupJob(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	type args struct {
		r db.Reader
		w db.Writer
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
				r: rw,
				w: rw,
			},
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "cleanupJob.newCleanupJob: missing db.Reader: parameter violation: error #100",
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			wantIsErr:  errors.InvalidParameter,
			wantErrMsg: "cleanupJob.newCleanupJob: missing db.Writer: parameter violation: error #100",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := newCleanupJob(ctx, tt.args.r, tt.args.w)
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

func TestRegisterJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	s := scheduler.TestScheduler(t, conn, wrapper)

	t.Run("succeeds", func(t *testing.T) {
		err := RegisterJob(context.Background(), s, rw, rw)
		require.NoError(t, err)
	})
	t.Run("fails-on-nil-scheduler", func(t *testing.T) {
		err := RegisterJob(context.Background(), nil, rw, rw)
		require.Error(t, err)
	})
	t.Run("fails-on-nil-db-writer", func(t *testing.T) {
		err := RegisterJob(context.Background(), s, rw, nil)
		require.Error(t, err)
	})
	t.Run("fails-on-nil-db-reader", func(t *testing.T) {
		err := RegisterJob(context.Background(), s, nil, rw)
		require.Error(t, err)
	})
}
