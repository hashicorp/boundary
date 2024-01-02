// Copyright (c) HashiCorp, Inc.
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

func TestHasAction(t *testing.T) {
	tests := []struct {
		name    string
		actions ActionSet
		action  Type
		want    bool
	}{
		{
			name:    "has 1",
			actions: ActionSet{Read, AuthorizeSession},
			action:  Read,
			want:    true,
		},
		{
			name:    "has 2",
			actions: ActionSet{Read, AuthorizeSession},
			action:  AuthorizeSession,
			want:    true,
		},
		{
			name:    "empty",
			actions: ActionSet{},
			action:  AuthorizeSession,
			want:    false,
		},
		{
			name:    "does not have 1",
			actions: ActionSet{Read, AuthorizeSession},
			action:  ReadSelf,
			want:    false,
		},
		{
			name:    "does not have 2",
			actions: ActionSet{Read, AuthorizeSession},
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
			actions: ActionSet{ReadSelf, CancelSelf},
			want:    true,
		},
		{
			name:    "has only self 2",
			actions: ActionSet{ReadSelf},
			want:    true,
		},
		{
			name:    "empty is false",
			actions: ActionSet{},
			want:    false,
		},
		{
			name:    "does not have only self 1",
			actions: ActionSet{Read, AuthorizeSession},
			want:    false,
		},
		{
			name:    "does not have only self 2",
			actions: ActionSet{ReadSelf, AuthorizeSession},
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
