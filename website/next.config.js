const withHashicorp = require('@hashicorp/platform-nextjs-plugin')
const path = require('path')
const redirects = require('./redirects.js')

// log out our primary environment variables for clarity in build logs
console.log(`HASHI_ENV: ${process.env.HASHI_ENV}`)
console.log(`NODE_ENV: ${process.env.NODE_ENV}`)
console.log(`VERCEL_ENV: ${process.env.VERCEL_ENV}`)
console.log(`MKTG_CONTENT_API: ${process.env.MKTG_CONTENT_API}`)
console.log(`ENABLE_VERSIONED_DOCS: ${process.env.ENABLE_VERSIONED_DOCS}`)

module.exports = withHashicorp({
  defaultLayout: true,
  mdx: { resolveIncludes: path.join(__dirname, 'pages/partials') },
  nextOptimizedImages: true,
})({
  async redirects() {
    return await redirects
  },
  svgo: { plugins: [{ removeViewBox: false }] },
  tipBranch: 'main',
  env: {
    HASHI_ENV: process.env.HASHI_ENV || 'development',
    SEGMENT_WRITE_KEY: 'JkNZiSgwVRAAFrkqqdHLxf0xfcZuhYYc',
    BUGSNAG_CLIENT_KEY: '635db43e199cb02419379291d573205b',
    BUGSNAG_SERVER_KEY: 'f85278a46e1b5565a9e91974cdc2843b',
    ENABLE_VERSIONED_DOCS: process.env.ENABLE_VERSIONED_DOCS || false,
  },
})
