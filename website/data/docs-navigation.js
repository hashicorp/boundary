// The root folder for this documentation category is `pages/docs`
//
// - A string refers to the name of a file
// - A "category" value refers to the name of a directory
// - All directories must have an "index.mdx" file to serve as
//   the landing page for the category, or a "name" property to
//   serve as the category title in the sidebar

export default [
  'security-model',
  {
    category: 'architecture',
    content: ['terminology', 'domain-model', 'reference-deployment'],
  },
  {
    category: 'configuration',
    content: ['auth-methods', 'projects', 'users', 'groups', 'roles', 'grants'],
  },
  {
    category: 'command-line',
    content: ['login'],
  },
  {
    category: 'admin-console',
    content: ['login'],
  },
  {
    category: 'sdk',
    content: ['login'],
  },

  '---',
  { title: 'External Link', href: 'https://www.hashicorp.com' },
]
