// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cleanup

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupJob(t *testing.T) {
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

	// ensure that the trigger works
	var count int
	err = db.QueryRowContext(ctx, "select count(public_id) from target_deleted").Scan(&count)
	if err != nil {
		t.Errorf("error checking target_deleted table %s", err)
	}
	require.Equal(t, 1, count)

	sJob := cleanupJob{
		w: rw,
	}

	err = sJob.Run(ctx)
	require.NoError(t, err)

	// ensure that the job doesn't clean up
	err = db.QueryRowContext(ctx, "select count(public_id) from target_deleted").Scan(&count)
	if err != nil {
		t.Errorf("error checking target_deleted table %s", err)
	}
	require.Equal(t, 1, count)

	_, err = db.Exec("update target_deleted set delete_time = $1", time.Now().AddDate(0, -2, 0))
	if err != nil {
		t.Errorf("error updating target_deleted %s", err)
	}

	err = sJob.Run(ctx)
	require.NoError(t, err)

	// ensure that the job did clean up
	err = db.QueryRowContext(ctx, "select count(public_id) from target_deleted").Scan(&count)
	if err != nil {
		t.Errorf("error checking target_deleted table %s", err)
	}
	require.Equal(t, 0, count)
}

func TestNewCleanupJob(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	type args struct {
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
				w: rw,
			},
		},
		{
			name: "nil-writer",
			args: args{
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
			got, err := newCleanupJob(ctx, tt.args.w)
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
