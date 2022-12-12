module.exports = [
  // define your custom redirects within this file.
  // vercel's redirect documentation: https://vercel.com/docs/project-configuration#project-configuration/redirects
  // example redirect:
  // {
  //   source: '/boundary/docs/some/path',
  //   destination: '/boundary/docs/some/other/path',
  //   permanent: true,
  // },
  {
    source: '/boundary/docs/what-is-boundary',
    destination: '/boundary/docs/overview/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/use-cases',
    destination: '/boundary/docs/overview/use-cases',
    permanent: true,
  },
  {
    source: '/boundary/docs/roadmap',
    destination: 'boundary/docs/overview/what-is-boundary',
    permanent: true,
  },
]
