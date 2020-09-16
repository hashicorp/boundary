// The root folder for this documentation category is `pages/docs`
//
// - A string refers to the name of a file
// - A "category" value refers to the name of a directory
// - All directories must have an "index.mdx" file to serve as
//   the landing page for the category, or a "name" property to
//   serve as the category title in the sidebar

export default [
  {
    category: 'introduction',
    content: [
      'security-model',
      'reference-architecture',
      {
        category: 'concepts',
        content: [
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
  {
    category: 'installing',
    content: ['dev-mode'],
  },
  {
    category: 'admin-console',
    content: ['login'],
  },
  {
    category: 'command-line',
    content: ['login'],
  },
  {
    category: 'sdk',
    content: ['login'],
  },
  {
    category: 'releases',
    content: ['release-notes', 'downloads'],
  },

  '---',
  { title: 'External Link', href: 'https://www.hashicorp.com' },
]
