package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsScope_Create(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	type args struct {
		authMethodId string
		claimsScope  string
	}
	tests := []struct {
		name               string
		args               args
		createResource     bool
		createWantErrMatch *errors.Template
		want               *ClaimsScope
		wantErrMatch       *errors.Template
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewClaimsScope(tt.args.authMethodId, tt.args.claimsScope)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "wanted error %s and got: %s", tt.wantErrMatch.Code, err.Error())
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.createResource {
				err := rw.Create(ctx, got)
				if tt.createWantErrMatch != nil {
					require.Error(err)
					assert.Truef(errors.Match(tt.createWantErrMatch, err), "wanted error %s and got: %s", tt.wantErrMatch.Code, err.Error())
					return
				}
				assert.NoError(err)
				found := AllocClaimsScope()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and scope = ?", tt.args.authMethodId, tt.args.claimsScope))
			}
		})
	}
}
