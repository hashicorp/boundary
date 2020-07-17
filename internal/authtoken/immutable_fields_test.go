package authtoken

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/db/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthToken_ImmutableFields(t *testing.T) {
	t.Parallel()
	wrapper := db.TestWrapper(t)
	conn, _ := db.TestSetup(t, "postgres")
	w := db.New(conn)

	ts := timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{Seconds: 0, Nanos: 0}}

	new := TestAuthToken(t, conn, wrapper)

	var tests = []struct {
		name           string
		update         *AuthToken
		fieldMask      []string
		wantRowUpdated int
	}{
		{
			name: "public_id",
			update: func() *AuthToken {
				c := new.clone()
				c.PublicId = "o_thisIsNotAValidId"
				return c
			}(),
			fieldMask: []string{"PublicId"},
		},
		{
			name: "create time",
			update: func() *AuthToken {
				c := new.clone()
				c.CreateTime = &ts
				return c
			}(),
			fieldMask: []string{"CreateTime"},
		},
		{
			name: "auth_account_id",
			update: func() *AuthToken {
				c := new.clone()
				c.AuthAccountId = "aa_01234567890"
				return c
			}(),
			fieldMask: []string{"AuthAccountId"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			orig := new.clone()
			err := w.LookupById(context.Background(), orig)
			require.NoError(err)

			rowsUpdated, err := w.Update(context.Background(), tt.update, tt.fieldMask, nil)
			require.Error(err)
			assert.Equal(tt.wantRowUpdated, rowsUpdated)

			after := new.clone()
			err = w.LookupById(context.Background(), after)
			require.NoError(err)

			assert.True(proto.Equal(orig, after))

		})
	}
}
