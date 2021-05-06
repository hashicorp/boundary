const withHashicorp = require('@hashicorp/nextjs-scripts')
const path = require('path')
const redirects = require('./redirects.js')

// log out our primary environment variables for clarity in build logs
console.log(`HASHI_ENV: ${process.env.HASHI_ENV}`)
console.log(`NODE_ENV: ${process.env.NODE_ENV}`)

module.exports = withHashicorp({
  defaultLayout: true,
  transpileModules: [
    'is-absolute-url',
    '@hashicorp/react-.*',
    '@hashicorp/versioned-docs',
  ],
  mdx: { resolveIncludes: path.join(__dirname, 'pages/partials') },
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
  },
})
