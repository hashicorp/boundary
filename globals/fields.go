package globals

// This set of consts is intended to be a place to collect commonly-used field
// names. Since these might be used outside of the internal code (e.g. by SDK or
// CLI), it's outside internal/ here in globals. Some of these are already const
// elsewhere in the code but we should migrate to using a single source.
const (
	IdField                          = "id"
	VersionField                     = "version"
	NameField                        = "name"
	DescriptionField                 = "description"
	CreatedTimeField                 = "created_time"
	UpdatedTimeField                 = "updated_time"
	TypeField                        = "type"
	AttributesField                  = "attributes"
	ScopeIdField                     = "scope_id"
	ScopeField                       = "scope"
	AuthMethodIdField                = "auth_method_id"
	AccountIdField                   = "account_id"
	UserIdField                      = "user_id"
	IsPrimaryField                   = "is_primary"
	AuthorizedActionsField           = "authorized_actions"
	AuthorizedCollectionActionsField = "authorized_collection_actions"
	ExpirationTimeField              = "expiration_time"
	ApproximateLastUsedTimeField     = "approximate_last_used_time"
	MembersField                     = "members"
	MemberIdsField                   = "member_ids"
	HostCatalogIdField               = "host_catalog_id"
	HostSetIdsField                  = "host_set_ids"
	HostSetsField                    = "host_sets"
)
