package job

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/job/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestJob_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")

	conn.LogMode(false)
	type args struct {
		name        string
		code        string
		description string
		privateId   string
		opts        []Option
	}

	futureTime := time.Now().Add(time.Hour)

	tests := []struct {
		name              string
		args              args
		want              *Job
		wantCreateErr     bool
		wantCreateErrCode errors.Code
		wantCreateErrMsg  string
		wantWriteErr      bool
		wantWriteErrCode  errors.Code
		wantWriteErrMsg   string
	}{
		{
			name: "missing-name",
			args: args{
				name: "",
			},
			wantCreateErr:     true,
			wantCreateErrCode: errors.InvalidParameter,
			wantCreateErrMsg:  "job.NewJob: missing name: parameter violation: error #100",
		},
		{
			name: "missing-code",
			args: args{
				name: "name",
			},
			wantCreateErr:     true,
			wantCreateErrCode: errors.InvalidParameter,
			wantCreateErrMsg:  "job.NewJob: missing code: parameter violation: error #100",
		},
		{
			name: "missing-description",
			args: args{
				name: "name",
				code: "code",
			},
			wantCreateErr:     true,
			wantCreateErrCode: errors.InvalidParameter,
			wantCreateErrMsg:  "job.NewJob: missing description: parameter violation: error #100",
		},
		{
			name: "valid-no-options",
			args: args{
				name:        "name",
				code:        "code",
				description: "description",
			},
			want: &Job{
				Job: &store.Job{
					Name:             "name",
					Description:      "description",
					Code:             "code",
					NextScheduledRun: testZeroTime,
				},
			},
		},
		{
			name: "duplicate-name-code",
			args: args{
				name:        "name",
				code:        "code",
				description: "description",
				privateId:   "job_duplicate-name",
			},
			want: &Job{
				Job: &store.Job{
					Name:             "name",
					Description:      "description",
					Code:             "code",
					NextScheduledRun: testZeroTime,
				},
			},
			wantWriteErr:     true,
			wantWriteErrCode: errors.NotUnique,
			wantWriteErrMsg:  "db.Create: create failed: duplicate key value violates unique constraint \"job_name_code_uq\": unique constraint violation: integrity violation: error #1002",
		},
		{
			name: "new-code",
			args: args{
				name:        "name",
				code:        "new-code",
				description: "description",
			},
			want: &Job{
				Job: &store.Job{
					Name:             "name",
					Code:             "new-code",
					Description:      "description",
					NextScheduledRun: testZeroTime,
				},
			},
		},
		{
			name: "new-name",
			args: args{
				name:        "new-name",
				code:        "code",
				description: "description",
			},
			want: &Job{
				Job: &store.Job{
					Name:             "new-name",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: testZeroTime,
				},
			},
		},
		{
			name: "valid-with-next-run",
			args: args{
				name:        "next-run-test",
				code:        "code",
				description: "description",
				opts: []Option{
					WithNextScheduledRun(futureTime),
				},
			},
			want: &Job{
				Job: &store.Job{
					Name:             "next-run-test",
					Code:             "code",
					Description:      "description",
					NextScheduledRun: &timestamp.Timestamp{Timestamp: timestamppb.New(futureTime)},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewJob(tt.args.name, tt.args.code, tt.args.description, tt.args.opts...)
			if tt.wantCreateErr {
				assert.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantCreateErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantCreateErrMsg, err.Error())
				return
			}
			assert.NoError(err)
			assert.NotNil(got)
			assert.Emptyf(got.PrivateId, "PrivateId set")
			assert.Equal(tt.want, got)

			id := tt.args.privateId
			if id == "" {
				// generate private id
				id, err = newJobId(got.Name, got.Code)
				assert.NoError(err)
			}
			tt.want.PrivateId = id
			got.PrivateId = id

			w := db.New(conn)
			err = w.Create(context.Background(), got)
			if tt.wantWriteErr {
				assert.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantWriteErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantWriteErrMsg, err.Error())
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestJob_SetTableName(t *testing.T) {
	defaultTableName := "job"
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
			def := &Job{
				Job: &store.Job{},
			}
			require.Equal(defaultTableName, def.TableName())
			s := &Job{
				Job:       &store.Job{},
				tableName: tt.initialName,
			}
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
