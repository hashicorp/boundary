package action

import "strings"

// Type defines a type for the Actions of Resources
// actions are also stored as a lookup db table named iam_action
type Type uint

// not using iota intentionally, since the values are stored in the db as well.
const (
	Unknown                   Type = 0
	List                      Type = 1
	Create                    Type = 2
	Update                    Type = 3
	Read                      Type = 4
	Delete                    Type = 5
	Authenticate              Type = 6
	All                       Type = 7
	AuthorizeSession          Type = 8
	AddGrants                 Type = 9
	RemoveGrants              Type = 10
	SetGrants                 Type = 11
	AddPrincipals             Type = 12
	SetPrincipals             Type = 13
	RemovePrincipals          Type = 14
	Deauthenticate            Type = 15
	AddMembers                Type = 16
	SetMembers                Type = 17
	RemoveMembers             Type = 18
	SetPassword               Type = 19
	ChangePassword            Type = 20
	AddHosts                  Type = 21
	SetHosts                  Type = 22
	RemoveHosts               Type = 23
	AddHostSets               Type = 24 // DEPRECATED
	SetHostSets               Type = 25 // DEPRECATED
	RemoveHostSets            Type = 26 // DEPRECATED
	Cancel                    Type = 27
	AddAccounts               Type = 28
	SetAccounts               Type = 29
	RemoveAccounts            Type = 30
	ReadSelf                  Type = 31
	CancelSelf                Type = 32
	ChangeState               Type = 33
	DeleteSelf                Type = 34
	NoOp                      Type = 35
	AddCredentialLibraries    Type = 36 // DEPRECATED
	SetCredentialLibraries    Type = 37 // DEPRECATED
	RemoveCredentialLibraries Type = 38 // DEPRECATED
	AddCredentialSources      Type = 39
	SetCredentialSources      Type = 40
	RemoveCredentialSources   Type = 41
	AddHostSources            Type = 42
	SetHostSources            Type = 43
	RemoveHostSources         Type = 44

	// When adding new actions, be sure to update:
	//
	// * The Test_AnonRestrictions test
)

var Map = map[string]Type{
	Create.String():                    Create,
	List.String():                      List,
	Update.String():                    Update,
	Read.String():                      Read,
	Delete.String():                    Delete,
	Authenticate.String():              Authenticate,
	All.String():                       All,
	AuthorizeSession.String():          AuthorizeSession,
	AddGrants.String():                 AddGrants,
	RemoveGrants.String():              RemoveGrants,
	SetGrants.String():                 SetGrants,
	AddPrincipals.String():             AddPrincipals,
	SetPrincipals.String():             SetPrincipals,
	RemovePrincipals.String():          RemovePrincipals,
	Deauthenticate.String():            Deauthenticate,
	AddMembers.String():                AddMembers,
	SetMembers.String():                SetMembers,
	RemoveMembers.String():             RemoveMembers,
	SetPassword.String():               SetPassword,
	ChangePassword.String():            ChangePassword,
	AddHosts.String():                  AddHosts,
	SetHosts.String():                  SetHosts,
	RemoveHosts.String():               RemoveHosts,
	AddHostSets.String():               AddHostSets,
	SetHostSets.String():               SetHostSets,
	RemoveHostSets.String():            RemoveHostSets,
	Cancel.String():                    Cancel,
	AddAccounts.String():               AddAccounts,
	SetAccounts.String():               SetAccounts,
	RemoveAccounts.String():            RemoveAccounts,
	ReadSelf.String():                  ReadSelf,
	CancelSelf.String():                CancelSelf,
	ChangeState.String():               ChangeState,
	DeleteSelf.String():                DeleteSelf,
	NoOp.String():                      NoOp,
	AddCredentialLibraries.String():    AddCredentialLibraries,
	SetCredentialLibraries.String():    SetCredentialLibraries,
	RemoveCredentialLibraries.String(): RemoveCredentialLibraries,
	AddCredentialSources.String():      AddCredentialSources,
	SetCredentialSources.String():      SetCredentialSources,
	RemoveCredentialSources.String():   RemoveCredentialSources,
	AddHostSources.String():            AddHostSources,
	SetHostSources.String():            SetHostSources,
	RemoveHostSources.String():         RemoveHostSources,
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
		"add-credential-libraries",
		"set-credential-libraries",
		"remove-credential-libraries",
		"add-credential-sources",
		"set-credential-sources",
		"remove-credential-sources",
		"add-host-sources",
		"set-host-sources",
		"remove-host-sources",
	}[a]
}

// ActionSet stores a slice of action types
type ActionSet []Type

// Strings converts Actions into a slice of the actions' string equivalents
func (a ActionSet) Strings() []string {
	if a == nil {
		return nil
	}
	ret := make([]string, len(a))
	for i, act := range a {
		ret[i] = act.String()
	}
	return ret
}

// HasAction returns whether the action set contains the given action.
func (a ActionSet) HasAction(act Type) bool {
	for _, v := range a {
		if v == act {
			return true
		}
	}
	return false
}

// OnlySelf returns true if all actions in the action set are self types. An
// empty set returns false. This may not be what you want so the caller should
// validate length and act appropriately as well.
func (a ActionSet) OnlySelf() bool {
	if len(a) == 0 {
		return false
	}
	for _, v := range a {
		if !strings.HasSuffix(v.String(), ":self") {
			return false
		}
	}
	return true
}
