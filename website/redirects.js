module.exports = [
  // define your custom redirects within this file.
  // vercel's redirect documentation: https://vercel.com/docs/configuration#project/redirects

  /////////////////////////////////
  // DOMAIN MODEL CONCEPTS
  /////////////////////////////////
  {
    source: '/help/admin-ui/orgs',
    destination: '/docs/concepts/domain-model/organizations',
    permanent: false,
  },
  {
    source: '/help/admin-ui/projects',
    destination: '/docs/concepts/domain-model/projects',
    permanent: false,
  },
  {
    source: '/help/admin-ui/users',
    destination: '/docs/concepts/domain-model/users',
    permanent: false,
  },
  {
    source: '/help/admin-ui/groups',
    destination: '/docs/concepts/domain-model/groups',
    permanent: false,
  },
  {
    source: '/help/admin-ui/roles',
    destination: '/docs/concepts/domain-model/roles',
    permanent: false,
  },
  {
    source: '/help/admin-ui/auth-methods',
    destination: '/docs/concepts/domain-model/auth-methods',
    permanent: false,
  },
  {
    source: '/help/admin-ui/projects',
    destination: '/docs/concepts/domain-model/projects',
    permanent: false,
  },
  {
    source: '/help/admin-ui/grants',
    destination: '/docs/concepts/domain-model/grants',
    permanent: false,
  },
  {
    source: '/help/admin-ui/host-catalogs',
    destination: '/docs/concepts/domain-model/host-catalogs',
    permanent: false,
  },
  {
    source: '/help/admin-ui/host-sets',
    destination: '/docs/concepts/domain-model/host-sets',
    permanent: false,
  },
  {
    source: '/help/admin-ui/hosts',
    destination: '/docs/concepts/domain-model/hosts',
    permanent: false,
  },
  {
    source: '/help/admin-ui/sessions',
    destination: '/docs/common-workflows/sessions',
    permanent: false,
  },

  ////////////////////////////////////////////
  // Adding sub-resources to existing resource
  ////////////////////////////////////////////
  // below for add principals workflow within roles
  {
    source: '/help/admin-ui/roles/add-principals',
    destination: '/docs/common-workflows/manage-identities',
    permanent: false,
  },
  // below for add members workflow within groups
  {
    source: '/help/admin-ui/groups/add-members',
    destination: '/docs/common-workflows/manage-identities',
    permanent: false,
  },
  {
    source: '/help/admin-ui/targets/add-host-sets',
    destination: '/docs/concepts/domain-model/host-sets',
    permanent: false,
  },
  {
    source: '/help/admin-ui/host-catalogs/add-hosts',
    destination: '/docs/concepts/domain-model/hosts',
    permanent: false,
  },

  ////////////////////////////////////////////
  // Creating new resources
  ////////////////////////////////////////////

  // below is for adding new accounts to an auth-method
  {
    source: '/help/admin-ui/accounts/new',
    destination: '/docs/common-workflows/manage-identities#create-account',
    permanent: false,
  },
  // below for adding new scopes
  {
    source: '/help/admin-ui/orgs/new',
    destination: '/docs/common-workflows/manage-scopes',
    permanent: false,
  },
  {
    source: '/help/admin-ui/projects/new',
    destination: '/docs/common-workflows/manage-scopes',
    permanent: false,
  },
  {
    source: '/help/admin-ui/targets/new',
    destination: '/docs/common-workflows/manage-targets',
    permanent: false,
  },
  {
    source: '/help/admin-ui/host-catalogs/new',
    destination: '/docs/common-workflows/manage-targets',
    permanent: false,
  },
  {
    source: '/help/admin-ui/host-sets/new',
    destination: '/docs/common-workflows/manage-targets#define-a-host-set',
    permanent: false,
  },
  {
    source: '/help/admin-ui/hosts/new',
    destination: '/docs/common-workflows/manage-targets#define-a-host',
    permanent: false,
  },
]
