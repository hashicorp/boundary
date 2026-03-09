// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
		{
			action: ChangeState,
			want:   "change-state",
		},
		{
			action: DeleteSelf,
			want:   "delete:self",
		},
		{
			action: NoOp,
			want:   "no-op",
		},
		{
			action: CreateWorkerLed,
			want:   "create:worker-led",
		},
		{
			action: AddWorkerTags,
			want:   "add-worker-tags",
		},
		{
			action: SetWorkerTags,
			want:   "set-worker-tags",
		},
		{
			action: RemoveWorkerTags,
			want:   "remove-worker-tags",
		},
		{
			action: CreateControllerLed,
			want:   "create:controller-led",
		},
		{
			action: ListScopeKeys,
			want:   "list-keys",
		},
		{
			action: RotateScopeKeys,
			want:   "rotate-keys",
		},
		{
			action: ListScopeKeyVersionDestructionJobs,
			want:   "list-key-version-destruction-jobs",
		},
		{
			action: DestroyScopeKeyVersion,
			want:   "destroy-key-version",
		},
		{
			action: Download,
			want:   "download",
		},
		{
			action: AttachStoragePolicy,
			want:   "attach-storage-policy",
		},
		{
			action: DetachStoragePolicy,
			want:   "detach-storage-policy",
		},
		{
			action: ReApplyStoragePolicy,
			want:   "reapply-storage-policy",
		},
		{
			action: AddGrantScopes,
			want:   "add-grant-scopes",
		},
		{
			action: SetGrantScopes,
			want:   "set-grant-scopes",
		},
		{
			action: RemoveGrantScopes,
			want:   "remove-grant-scopes",
		},
		{
			action: MonthlyActiveUsers,
			want:   "monthly-active-users",
		},
		{
			action: ListResolvableAliases,
			want:   "list-resolvable-aliases",
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
			actions: NewActionSet(Read, AuthorizeSession),
			want:    []string{"read", "authorize-session"},
		},
		{
			name:    "reverse test to check ordering",
			actions: NewActionSet(AuthorizeSession, Read),
			want:    []string{"authorize-session", "read"},
		},
		{
			name:    "another test",
			actions: NewActionSet(Delete, AddGrants),
			want:    []string{"delete", "add-grants"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: previously the order seemed to matter for these tests,
			// Is this really imporant? And if so, is simply having a stable
			// order sufficient?
			assert.ElementsMatch(t, tt.actions.Strings(), tt.want)
		})
	}
}

func TestHasAction(t *testing.T) {
	tests := []struct {
		name    string
		actions ActionSet
		action  Type
		want    bool
	}{
		{
			name:    "has 1",
			actions: NewActionSet(Read, AuthorizeSession),
			action:  Read,
			want:    true,
		},
		{
			name:    "has 2",
			actions: NewActionSet(Read, AuthorizeSession),
			action:  AuthorizeSession,
			want:    true,
		},
		{
			name:    "empty",
			actions: NewActionSet(),
			action:  AuthorizeSession,
			want:    false,
		},
		{
			name:    "does not have 1",
			actions: NewActionSet(Read, AuthorizeSession),
			action:  ReadSelf,
			want:    false,
		},
		{
			name:    "does not have 2",
			actions: NewActionSet(Read, AuthorizeSession),
			action:  Delete,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.actions.HasAction(tt.action))
		})
	}
}

func TestOnlySelf(t *testing.T) {
	tests := []struct {
		name    string
		actions ActionSet
		want    bool
	}{
		{
			name:    "has only self 1",
			actions: NewActionSet(ReadSelf, CancelSelf),
			want:    true,
		},
		{
			name:    "has only self 2",
			actions: NewActionSet(ReadSelf),
			want:    true,
		},
		{
			name:    "empty is false",
			actions: ActionSet{},
			want:    false,
		},
		{
			name:    "does not have only self 1",
			actions: NewActionSet(Read, AuthorizeSession),
			want:    false,
		},
		{
			name:    "does not have only self 2",
			actions: NewActionSet(ReadSelf, AuthorizeSession),
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.actions.OnlySelf())
		})
	}
}

func TestIsActionOrParent(t *testing.T) {
	tests := []struct {
		name string
		base Type
		comp Type
		want bool
	}{
		{
			name: "same",
			base: Cancel,
			comp: Cancel,
			want: true,
		},
		{
			name: "different",
			base: Cancel,
			comp: Read,
		},
		{
			name: "different base and comp",
			base: List,
			comp: CancelSelf,
		},
		{
			name: "same base and comp",
			base: Cancel,
			comp: CancelSelf,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.base.IsActionOrParent(tt.comp))
		})
	}
}

func TestNewActionSet(t *testing.T) {
	tests := []struct {
		name  string
		types []Type
		want  ActionSet
	}{
		{
			name:  "empty",
			types: []Type{},
			want:  make(ActionSet),
		},
		{
			name:  "single",
			types: []Type{List},
			want: ActionSet{
				List: struct{}{},
			},
		},
		{
			name:  "multiple",
			types: []Type{List, Create, Read, Update, Delete},
			want: ActionSet{
				List:   struct{}{},
				Create: struct{}{},
				Read:   struct{}{},
				Update: struct{}{},
				Delete: struct{}{},
			},
		},
		{
			name:  "multiple-duplicates",
			types: []Type{List, Read, List, Read, Create, Read, Update, Delete},
			want: ActionSet{
				List:   struct{}{},
				Create: struct{}{},
				Read:   struct{}{},
				Update: struct{}{},
				Delete: struct{}{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewActionSet(tt.types...)
			assert.Equal(t, tt.want, s)
		})
	}
}

func TestActionSetUnion(t *testing.T) {
	tests := []struct {
		name string
		sets []ActionSet
		want ActionSet
	}{
		{
			name: "empty",
			sets: []ActionSet{},
			want: ActionSet{},
		},
		{
			name: "one",
			sets: []ActionSet{
				{
					List:   struct{}{},
					Create: struct{}{},
					Read:   struct{}{},
				},
			},
			want: ActionSet{
				List:   struct{}{},
				Create: struct{}{},
				Read:   struct{}{},
			},
		},
		{
			name: "multiple-no-duplicates",
			sets: []ActionSet{
				{
					List:   struct{}{},
					Create: struct{}{},
				},
				{
					Update: struct{}{},
					Delete: struct{}{},
				},
				{
					Read: struct{}{},
				},
			},
			want: ActionSet{
				List:   struct{}{},
				Create: struct{}{},
				Read:   struct{}{},
				Update: struct{}{},
				Delete: struct{}{},
			},
		},
		{
			name: "multiple-duplicates",
			sets: []ActionSet{
				{
					List:   struct{}{},
					Create: struct{}{},
				},
				{
					List:   struct{}{},
					Update: struct{}{},
					Delete: struct{}{},
				},
				{
					Update: struct{}{},
					Read:   struct{}{},
				},
			},
			want: ActionSet{
				List:   struct{}{},
				Create: struct{}{},
				Read:   struct{}{},
				Update: struct{}{},
				Delete: struct{}{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Union(tt.sets...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestActionSetDifference(t *testing.T) {
	tests := []struct {
		name string
		a    ActionSet
		b    ActionSet
		want ActionSet
	}{
		{
			name: "same-set",
			a: ActionSet{
				List:   struct{}{},
				Update: struct{}{},
			},
			b: ActionSet{
				List:   struct{}{},
				Update: struct{}{},
			},
			want: ActionSet{},
		},
		{
			name: "distinct",
			a: ActionSet{
				List:   struct{}{},
				Update: struct{}{},
			},
			b: ActionSet{
				Read:   struct{}{},
				Delete: struct{}{},
			},
			want: ActionSet{
				List:   struct{}{},
				Update: struct{}{},
			},
		},
		{
			name: "some-overlap",
			a: ActionSet{
				List:   struct{}{},
				Update: struct{}{},
			},
			b: ActionSet{
				Read:   struct{}{},
				List:   struct{}{},
				Delete: struct{}{},
			},
			want: ActionSet{
				Update: struct{}{},
			},
		},
		{
			name: "nil-a",
			a:    nil,
			b: ActionSet{
				Read:   struct{}{},
				List:   struct{}{},
				Delete: struct{}{},
			},
			want: ActionSet{},
		},
		{
			name: "nil-b",
			a: ActionSet{
				Read:   struct{}{},
				List:   struct{}{},
				Delete: struct{}{},
			},
			b: nil,
			want: ActionSet{
				Read:   struct{}{},
				List:   struct{}{},
				Delete: struct{}{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Difference(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}
