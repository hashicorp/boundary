module.exports = [
  // define your custom rewrites within this file.
  // vercel's rewrites documentation: https://vercel.com/docs/configuration#project/rewrites
  {
    source: '/api/:splat*',
    destination: '/api-docs/:splat*',
  },
]
