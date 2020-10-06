// The root folder for this documentation category is `pages/docs`
//
// - A string refers to the name of a file
// - A "category" value refers to the name of a directory
// - All directories must have an "index.mdx" file to serve as
//   the landing page for the category, or a "name" property to
//   serve as the category title in the sidebar

export default [
  {
    category: 'getting-started',
    content: ['run-and-login', 'connect-to-target'],
  },
  {
    category: 'installing',
    content: [
		  'systemd',
		  'postgres',
		  'high-availability',
		],
  },
  {
    category: 'developing',
    content: [
      'building',
      'ui',
      {
        category: 'sdk',
        content: ['authenticate'],
      },
    ],
  },
  {
    category: 'concepts',
    content: [
      'api-standards',
      'cli-standards',
      'permissions',
      'security-model',
      {
        category: 'domain-model',
        content: [
				  'accounts',
          'actions',
          'auth-methods',
          'grants',
          'groups',
          'hosts',
          'host-catalogs',
          'host-sets',
          'organization',
          'principals',
          'projects',
          'resources',
          'scopes',
          'targets',
          'roles',
          'users',
        ],
      },
    ],
  },
  '---',
  {
    category: 'configuration',
    content: [
      {
        category: 'listener',
        content: ['tcp'],
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
      'telemetry',
    ],
  },
  {
    category: 'common-workflows',
    content: [
      'manage-scopes',
      'manage-targets',
      'manage-identities',
      'manage-sessions',
    ],
  },
  '---',
  {
    category: 'roadmap',
    content: ['v0_2_0'],
  },
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
