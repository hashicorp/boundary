package job

import (
	"strings"
	"testing"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Ids(t *testing.T) {
	t.Parallel()
	type args struct {
		name string
		code string
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantErrCode errors.Code
		wantErrMsg  string
	}{
		{
			name:        "missing-name",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewJobId: missing name: parameter violation: error #100",
		},
		{
			name: "missing-code",
			args: args{
				name: "name",
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
			wantErrMsg:  "job.NewJobId: missing code: parameter violation: error #100",
		},
		{
			name: "valid",
			args: args{
				name: "name",
				code: "code",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewJobId(tt.args.name, tt.args.code)
			if tt.wantErr {
				require.Error(err)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				assert.Equal(tt.wantErrMsg, err.Error())
				return
			}
			require.NoError(err)
			assert.True(strings.HasPrefix(got, JobPrefix+"_"))
		})
	}

	t.Run("sameName", func(t *testing.T) {
		id, err := NewJobId("name", "code")
		require.NoError(t, err)

		id1, err := NewJobId("name", "code")
		require.NoError(t, err)

		assert.Equal(t, id, id1)
	})
	t.Run("differentName", func(t *testing.T) {
		id, err := NewJobId("name", "code")
		require.NoError(t, err)

		id1, err := NewJobId("different name", "code")
		require.NoError(t, err)

		assert.NotEqual(t, id, id1)
	})
	t.Run("differentCode", func(t *testing.T) {
		id, err := NewJobId("name", "code")
		require.NoError(t, err)

		id1, err := NewJobId("name", "different code")
		require.NoError(t, err)

		assert.NotEqual(t, id, id1)
	})
}
