// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package action

import (
	"fmt"
	"strings"
)

type Type uint

const (
	Unknown                            Type = 0
	List                               Type = 1
	Create                             Type = 2
	Update                             Type = 3
	Read                               Type = 4
	Delete                             Type = 5
	Authenticate                       Type = 6
	All                                Type = 7
	AuthorizeSession                   Type = 8
	AddGrants                          Type = 9
	RemoveGrants                       Type = 10
	SetGrants                          Type = 11
	AddPrincipals                      Type = 12
	SetPrincipals                      Type = 13
	RemovePrincipals                   Type = 14
	Deauthenticate                     Type = 15
	AddMembers                         Type = 16
	SetMembers                         Type = 17
	RemoveMembers                      Type = 18
	SetPassword                        Type = 19
	ChangePassword                     Type = 20
	AddHosts                           Type = 21
	SetHosts                           Type = 22
	RemoveHosts                        Type = 23
	AddHostSets                        Type = 24 // OBSOLETE
	SetHostSets                        Type = 25 // OBSOLETE
	RemoveHostSets                     Type = 26 // OBSOLETE
	Cancel                             Type = 27
	AddAccounts                        Type = 28
	SetAccounts                        Type = 29
	RemoveAccounts                     Type = 30
	ReadSelf                           Type = 31
	CancelSelf                         Type = 32
	ChangeState                        Type = 33
	DeleteSelf                         Type = 34
	NoOp                               Type = 35
	AddCredentialLibraries             Type = 36 // DEPRECATED
	SetCredentialLibraries             Type = 37 // DEPRECATED
	RemoveCredentialLibraries          Type = 38 // DEPRECATED
	AddCredentialSources               Type = 39
	SetCredentialSources               Type = 40
	RemoveCredentialSources            Type = 41
	AddHostSources                     Type = 42
	SetHostSources                     Type = 43
	RemoveHostSources                  Type = 44
	CreateWorkerLed                    Type = 45
	AddWorkerTags                      Type = 46
	SetWorkerTags                      Type = 47
	RemoveWorkerTags                   Type = 48
	CreateControllerLed                Type = 49
	ReinitializeCertificateAuthority   Type = 50
	ReadCertificateAuthority           Type = 51
	ListScopeKeys                      Type = 52
	RotateScopeKeys                    Type = 53
	ListScopeKeyVersionDestructionJobs Type = 54
	DestroyScopeKeyVersion             Type = 55
	Download                           Type = 56
	AttachStoragePolicy                Type = 57
	DetachStoragePolicy                Type = 58
	ReApplyStoragePolicy               Type = 59
	AddGrantScopes                     Type = 60
	SetGrantScopes                     Type = 61
	RemoveGrantScopes                  Type = 62
	MonthlyActiveUsers                 Type = 63
	ListResolvableAliases              Type = 64

	// When adding new actions, be sure to update:
	//
	// * The Test_AnonRestrictions test: update the following line to include the last action:
	// 		for j := action.Type(1); j <= action.<action>; j++ {
)

var Map = map[string]Type{
	Create.String():                             Create,
	List.String():                               List,
	Update.String():                             Update,
	Read.String():                               Read,
	Delete.String():                             Delete,
	Authenticate.String():                       Authenticate,
	All.String():                                All,
	AuthorizeSession.String():                   AuthorizeSession,
	AddGrants.String():                          AddGrants,
	RemoveGrants.String():                       RemoveGrants,
	SetGrants.String():                          SetGrants,
	AddPrincipals.String():                      AddPrincipals,
	SetPrincipals.String():                      SetPrincipals,
	RemovePrincipals.String():                   RemovePrincipals,
	Deauthenticate.String():                     Deauthenticate,
	AddMembers.String():                         AddMembers,
	SetMembers.String():                         SetMembers,
	RemoveMembers.String():                      RemoveMembers,
	SetPassword.String():                        SetPassword,
	ChangePassword.String():                     ChangePassword,
	AddHosts.String():                           AddHosts,
	SetHosts.String():                           SetHosts,
	RemoveHosts.String():                        RemoveHosts,
	AddHostSets.String():                        AddHostSets,
	SetHostSets.String():                        SetHostSets,
	RemoveHostSets.String():                     RemoveHostSets,
	Cancel.String():                             Cancel,
	AddAccounts.String():                        AddAccounts,
	SetAccounts.String():                        SetAccounts,
	RemoveAccounts.String():                     RemoveAccounts,
	ReadSelf.String():                           ReadSelf,
	CancelSelf.String():                         CancelSelf,
	ChangeState.String():                        ChangeState,
	DeleteSelf.String():                         DeleteSelf,
	NoOp.String():                               NoOp,
	AddCredentialLibraries.String():             AddCredentialLibraries,
	SetCredentialLibraries.String():             SetCredentialLibraries,
	RemoveCredentialLibraries.String():          RemoveCredentialLibraries,
	AddCredentialSources.String():               AddCredentialSources,
	SetCredentialSources.String():               SetCredentialSources,
	RemoveCredentialSources.String():            RemoveCredentialSources,
	AddHostSources.String():                     AddHostSources,
	SetHostSources.String():                     SetHostSources,
	RemoveHostSources.String():                  RemoveHostSources,
	CreateWorkerLed.String():                    CreateWorkerLed,
	AddWorkerTags.String():                      AddWorkerTags,
	SetWorkerTags.String():                      SetWorkerTags,
	RemoveWorkerTags.String():                   RemoveWorkerTags,
	CreateControllerLed.String():                CreateControllerLed,
	ReinitializeCertificateAuthority.String():   ReinitializeCertificateAuthority,
	ReadCertificateAuthority.String():           ReadCertificateAuthority,
	ListScopeKeys.String():                      ListScopeKeys,
	RotateScopeKeys.String():                    RotateScopeKeys,
	ListScopeKeyVersionDestructionJobs.String(): ListScopeKeyVersionDestructionJobs,
	DestroyScopeKeyVersion.String():             DestroyScopeKeyVersion,
	Download.String():                           Download,
	AttachStoragePolicy.String():                AttachStoragePolicy,
	DetachStoragePolicy.String():                DetachStoragePolicy,
	ReApplyStoragePolicy.String():               ReApplyStoragePolicy,
	AddGrantScopes.String():                     AddGrantScopes,
	SetGrantScopes.String():                     SetGrantScopes,
	RemoveGrantScopes.String():                  RemoveGrantScopes,
	MonthlyActiveUsers.String():                 MonthlyActiveUsers,
	ListResolvableAliases.String():              ListResolvableAliases,
}

var DeprecatedMap = map[string]Type{
	AddHostSets.String():               AddHostSources,
	SetHostSets.String():               SetHostSources,
	RemoveHostSets.String():            RemoveHostSources,
	AddCredentialLibraries.String():    AddCredentialSources,
	SetCredentialLibraries.String():    SetCredentialSources,
	RemoveCredentialLibraries.String(): RemoveCredentialSources,
}

func (a Type) String() string {
	return [...]string{
		"unknown",
		"list",
		"create",
		"update",
		"read",
		"delete",
		"authenticate",
		"*",
		"authorize-session",
		"add-grants",
		"remove-grants",
		"set-grants",
		"add-principals",
		"set-principals",
		"remove-principals",
		"deauthenticate",
		"add-members",
		"set-members",
		"remove-members",
		"set-password",
		"change-password",
		"add-hosts",
		"set-hosts",
		"remove-hosts",
		"add-host-sets",
		"set-host-sets",
		"remove-host-sets",
		"cancel",
		"add-accounts",
		"set-accounts",
		"remove-accounts",
		"read:self",
		"cancel:self",
		"change-state",
		"delete:self",
		"no-op",
		"add-credential-libraries",    // DEPRECATED
		"set-credential-libraries",    // DEPRECATED
		"remove-credential-libraries", // DEPRECATED
		"add-credential-sources",
		"set-credential-sources",
		"remove-credential-sources",
		"add-host-sources",
		"set-host-sources",
		"remove-host-sources",
		"create:worker-led",
		"add-worker-tags",
		"set-worker-tags",
		"remove-worker-tags",
		"create:controller-led",
		"reinitialize-certificate-authority",
		"read-certificate-authority",
		"list-keys",
		"rotate-keys",
		"list-key-version-destruction-jobs",
		"destroy-key-version",
		"download",
		"attach-storage-policy",
		"detach-storage-policy",
		"reapply-storage-policy",
		"add-grant-scopes",
		"set-grant-scopes",
		"remove-grant-scopes",
		"monthly-active-users",
		"list-resolvable-aliases",
	}[a]
}

// IsActionOrParent tests whether the given action is either the same as the
// suspect or is a parent of the suspect. This is used in some parts of ACL
// checking.
func (a Type) IsActionOrParent(suspect Type) bool {
	if a == suspect {
		return true
	}
	return strings.HasPrefix(suspect.String(), fmt.Sprintf("%s:", a.String()))
}

// ActionSet is a set of action.Type.
type ActionSet map[Type]struct{}

// NewActionSet creates an ActionSet.
func NewActionSet(t ...Type) ActionSet {
	a := make(ActionSet, len(t))
	a.Add(t...)
	return a
}

// Add adds the provided Types t to a, any duplicates are ignored.
func (a ActionSet) Add(t ...Type) {
	for _, tt := range t {
		a[tt] = struct{}{}
	}
}

// Union returns a new ActionSet that is the union of the sets.
func Union(sets ...ActionSet) ActionSet {
	a := make(ActionSet)
	for _, s := range sets {
		for k := range s {
			a.Add(k)
		}
	}
	return a
}

// Difference returns a new ActionSet that is the difference of a-b.
func Difference(a ActionSet, b ActionSet) ActionSet {
	c := make(ActionSet)
	for t := range a {
		if !b.HasAction(t) {
			c.Add(t)
		}
	}
	return c
}

// Strings converts Actions into a slice of the actions' string equivalents
func (a ActionSet) Strings() []string {
	if a == nil {
		return nil
	}
	ret := make([]string, 0, len(a))
	for act := range a {
		ret = append(ret, act.String())
	}
	return ret
}

// HasAction returns whether the action set contains the given action.
func (a ActionSet) HasAction(act Type) bool {
	_, ok := a[act]
	return ok
}

// OnlySelf returns true if all actions in the action set are self types. An
// empty set returns false. This may not be what you want so the caller should
// validate length and act appropriately as well.
func (a ActionSet) OnlySelf() bool {
	if len(a) == 0 {
		return false
	}
	for v := range a {
		if !strings.HasSuffix(v.String(), ":self") {
			return false
		}
	}
	return true
}
