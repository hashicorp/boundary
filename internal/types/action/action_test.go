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
			action: AuthorizeSession,
			want:   "authorize-session",
		},
		{
			action: AddGrants,
			want:   "add-grants",
		},
		{
			action: RemoveGrants,
			want:   "remove-grants",
		},
		{
			action: SetGrants,
			want:   "set-grants",
		},
		{
			action: AddPrincipals,
			want:   "add-principals",
		},
		{
			action: RemovePrincipals,
			want:   "remove-principals",
		},
		{
			action: SetPrincipals,
			want:   "set-principals",
		},
		{
			action: Deauthenticate,
			want:   "deauthenticate",
		},
		{
			action: ReadSelf,
			want:   "read:self",
		},
		{
			action: CancelSelf,
			want:   "cancel:self",
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equalf(t, tt.want, tt.action.String(), "unexpected action string for %s", tt.want)
			assert.Equalf(t, tt.action, Map[tt.want], "unexpected action from map for %s", tt.want)
		})
	}
}

func TestActionStrings(t *testing.T) {
	tests := []struct {
		name    string
		actions ActionSet
		want    []string
	}{
		{
			name:    "basic test",
			actions: ActionSet{Read, AuthorizeSession},
			want:    []string{"read", "authorize-session"},
		},
		{
			name:    "reverse test to check ordering",
			actions: ActionSet{AuthorizeSession, Read},
			want:    []string{"authorize-session", "read"},
		},
		{
			name:    "another test",
			actions: ActionSet{Delete, AddGrants},
			want:    []string{"delete", "add-grants"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.actions.Strings(), tt.want)
		})
	}
}
