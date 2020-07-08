package action

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAction(t *testing.T) {
	tests := []struct {
		action Type
		want   string
	}{
		{
			action: Unknown,
			want:   "unknown",
		},
		{
			action: List,
			want:   "list",
		},
		{
			action: Create,
			want:   "create",
		},
		{
			action: Update,
			want:   "update",
		},
		{
			action: Read,
			want:   "read",
		},
		{
			action: Delete,
			want:   "delete",
		},
		{
			action: Authenticate,
			want:   "authenticate",
		},
		{
			action: All,
			want:   "*",
		},
		{
			action: Connect,
			want:   "connect",
		},
		{
			action: AddGrants,
			want:   "add-grants",
		},
		{
			action: DeleteGrants,
			want:   "delete-grants",
		},
		{
			action: SetGrants,
			want:   "set-grants",
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.action.String(), "unexpected action string for %s", tt.want)
			assert.Equalf(t, tt.action, Map[tt.want], "unexpected action from map for %s", tt.want)
		})
	}
}
