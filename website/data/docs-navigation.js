// The root folder for this documentation category is `pages/docs`
//
// - A string refers to the name of a file
// - A "category" value refers to the name of a directory
// - All directories must have an "index.mdx" file to serve as the landing page
//   for the category, or a "name" property to serve as the category title in
//   the sidebar

export default [
  {
    category: 'getting-started',
    content: ['run-and-login', 'connect-to-target'],
  },
  {
    category: 'installing',
    content: ['no-gen-resources', 'systemd', 'postgres', 'high-availability'],
  },
  {
    category: 'api-clients',
    content: ['api', 'cli', 'go-sdk', 'desktop'],
  },
  {
    category: 'concepts',
    content: [
      {
        category: 'security',
        content: ['permissions', 'data-encryption', 'connections-tls'],
      },
      {
        category: 'domain-model',
        content: [
          'accounts',
          'auth-methods',
          'groups',
          'hosts',
          'host-catalogs',
          'host-sets',
          'scopes',
          'sessions',
          'targets',
          'roles',
          'users',
        ],
      },
      {
        category: 'filtering',
        content: ['resource-listing', 'worker-tags'],
      },
    ],
  },
  {
    category: 'developing',
    content: ['building', 'ui'],
  },
  '---',
  {
    category: 'configuration',
    content: [
      {
        category: 'listener',
        content: ['tcp', 'unix'],
      },
      {
        category: 'kms',
        content: [
          'aead',
          'awskms',
          'alicloudkms',
          'azurekeyvault',
          'gcpckms',
          'ocikms',
          'transit',
        ],
      },
      'controller',
      'worker',
    ],
  },
  {
    title: 'Common Workflows',
    href: 'https://learn.hashicorp.com/collections/boundary/common-workflows',
  },
  '---',
  'roadmap',

  {
    category: 'releases',
    content: [
      {
        category: 'release-notes',
        content: ['v0_1_0'],
      },
    ],
  },
]
