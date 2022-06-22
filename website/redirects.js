module.exports = [
  // define your custom redirects within this file.
  // vercel's redirect documentation: https://vercel.com/docs/project-configuration#project-configuration/redirects

  // Top level redirect
  {
    source: '/home',
    destination: '/',
    permanent: true,
  },
  {
    source: '/help/admin-ui',
    destination: '/docs',
    permanent: false,
  },
  {
    source: '/help/admin-ui/downloads',
    destination: '/downloads',
    permanent: true,
  },

  // `/<path>/index.html` to /<path>
  {
    source: '/:splat*/index.html',
    destination: '/:splat*',
    permanent: true,
  },

  /////////////////////////////////
  // DESKTOP CLIENT
  /////////////////////////////////
  {
    source: '/help/desktop/targets',
    destination: '/docs/api-clients/desktop#connect',
    permanent: false,
  },
  {
    source: '/help/desktop/sessions',
    destination: '/docs/api-clients/desktop#connect',
    permanent: false,
  },
  {
    source: '/docs/api-clients/desktop',
    destination:
      'https://learn.hashicorp.com/tutorials/boundary/getting-started-desktop-app',
    permanent: true,
  },
  {
    source: '/help/admin-ui/getting-started/desktop',
    destination:
      'https://learn.hashicorp.com/tutorials/boundary/getting-started-desktop-app',
    permanent: true,
  },

  /////////////////////////////////
  // API CLIENT
  /////////////////////////////////
  {
    source: '/help/admin-ui/api-client/cli',
    destination:
      '/docs/api-clients/cli',
    permanent: true,
  },
  {
    source: '/help/admin-ui/api-client/api',
    destination:
      '/docs/api-clients/api',
    permanent: true,
  },

  /////////////////////////////////
  // DOMAIN MODEL CONCEPTS
  /////////////////////////////////
  {
    source: '/help/admin-ui/orgs',
    destination: '/docs/concepts/domain-model/scopes#organizations',
    permanent: false,
  },
  {
    source: '/help/admin-ui/projects',
    destination: '/docs/concepts/domain-model/scopes#projects',
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
    source: '/help/admin-ui/accounts',
    destination: '/docs/concepts/domain-model/accounts',
    permanent: false,
  },
  {
    source: '/help/admin-ui/projects',
    destination: '/docs/concepts/domain-model/scopes#projects',
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
    source: '/help/admin-ui/targets',
    destination: '/docs/concepts/domain-model/targets',
    permanent: false,
  },
  {
    source: '/help/admin-ui/sessions',
    destination: '/docs/concepts/domain-model/sessions',
    permanent: false,
  },
  {
    source: '/help/admin-ui/credential-stores',
    destination: '/docs/concepts/domain-model/credential-stores',
    permanent: false,
  },
  {
    source: '/help/admin-ui/credential-libraries',
    destination: '/docs/concepts/domain-model/credential-libraries',
    permanent: false,
  },
  {
    source: '/help/admin-ui/managed-groups',
    destination: '/docs/concepts/domain-model/managed-groups',
    permanent: false,
  },
  {
    source: '/help/admin-ui/dynamic-host-catalogs-on-aws',
    destination:
      'https://learn.hashicorp.com/tutorials/boundary/aws-host-catalogs',
    permanent: false,
  },
  {
    source: '/help/admin-ui/dynamic-host-catalogs-on-azure',
    destination:
      'https://learn.hashicorp.com/tutorials/boundary/azure-host-catalogs',
    permanent: false,
  },
  {
    source: '/help/admin-ui/targets/worker-filters',
    destination: '/docs/concepts/filtering/worker-tags#target-worker-filtering',
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
    source: '/help/admin-ui/host-sets/add-hosts',
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

  ////////////////////////////////////////////
  // OSS content migration
  ////////////////////////////////////////////

  // below is for moved /installing to /oss/installing

  {
    source: '/docs/installing/:splat*',
    destination: '/docs/oss/installing/:splat*',
    permanent: true,
  },

  // below is for moved /operations to /oss/operations

  {
    source: '/docs/operations/:splat*',
    destination: '/docs/oss/operations/:splat*',
    permanent: true,
  },

  // below is for moved /developing to /oss/developing

  {
    source: '/docs/developing/:splat*',
    destination: '/docs/oss/developing/:splat*',
    permanent: true,
  },
]
