package job

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobRun_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)

	conn.LogMode(false)

	type args struct {
		jobId    string
		serverId string
	}

	tests := []struct {
		name        string
		args        args
		opts        []Option
		want        *JobRun
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name: "missing job id",
			args: args{
				jobId: "",
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewJobRun: missing job id: parameter violation: error #100",
		},
		{
			name: "missing server id",
			args: args{
				jobId: "job_1234567890",
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewJobRun: missing server id: parameter violation: error #100",
		},
		{
			name: "invalid run status",
			args: args{
				jobId:    "job_1234567890",
				serverId: "test-server",
			},
			opts: []Option{
				WithJobRunStatus("bad-status"),
			},
			want:        nil,
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewJobRun: invalid run status: bad-status: parameter violation: error #100",
		},
		{
			name: "valid",
			args: args{
				jobId:    "job_1234567890",
				serverId: "test-server",
			},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:    "job_1234567890",
					ServerId: "test-server",
					Status:   string(Running),
				},
			},
		},
		{
			name: "valid-with-run-status",
			args: args{
				jobId:    "job_1234567890",
				serverId: "test-server",
			},
			opts: []Option{
				WithJobRunStatus(Completed),
			},
			want: &JobRun{
				JobRun: &store.JobRun{
					JobId:    "job_1234567890",
					ServerId: "test-server",
					Status:   string(Completed),
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewJobRun(tt.args.jobId, tt.args.serverId, tt.opts...)
			if tt.wantErr {
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(got)
			assert.Equal(tt.want, got)
		})
	}

	t.Run("conflicting-job-run", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)

		server := testController(t, conn, wrapper)

		job1 := testJob(t, conn, "job1", "code1", "description")
		require.NotNil(job1)

		run, err := NewJobRun(job1.PrivateId, server.PrivateId)
		require.NoError(err)
		require.NotNil(run)

		err = rw.Create(context.Background(), run)
		assert.NoError(err)

		// Insert same job run should conflict on jobId and status
		run, err = NewJobRun(job1.PrivateId, server.PrivateId)
		require.NoError(err)
		require.NotNil(run)

		err = rw.Create(context.Background(), run)
		assert.Error(err)
		assert.Equal("db.Create: create failed: duplicate key value violates unique constraint \"job_run_status_constraint\": unique constraint violation: integrity violation: error #1002", err.Error())

		// Creating a new job with a different name and the run should not conflict
		job2 := testJob(t, conn, "job2", "code1", "description")
		require.NotNil(job1)

		run, err = NewJobRun(job2.PrivateId, server.PrivateId)
		require.NoError(err)
		require.NotNil(run)

		err = rw.Create(context.Background(), run)
		assert.NoError(err)

		// Creating a new job with same name and different code should not conflict
		job1withCode := testJob(t, conn, "job1", "code2", "description")
		require.NotNil(job1)

		run, err = NewJobRun(job1withCode.PrivateId, server.PrivateId)
		require.NoError(err)
		require.NotNil(run)

		err = rw.Create(context.Background(), run)
		assert.NoError(err)
	})
}

func TestJobRun_SetTableName(t *testing.T) {
	defaultTableName := "job_run"
	tests := []struct {
		name        string
		initialName string
		setNameTo   string
		want        string
	}{
		{
			name:        "new-name",
			initialName: "",
			setNameTo:   "new-name",
			want:        "new-name",
		},
		{
			name:        "reset to default",
			initialName: "initial",
			setNameTo:   "",
			want:        defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := &JobRun{
				JobRun: &store.JobRun{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &JobRun{
				JobRun:    &store.JobRun{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
