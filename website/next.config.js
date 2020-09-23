const withHashicorp = require('@hashicorp/nextjs-scripts')
const path = require('path')

// log out our primary environment variables for clarity in build logs
console.log(`HASHI_ENV: ${process.env.HASHI_ENV}`)
console.log(`NODE_ENV: ${process.env.NODE_ENV}`)
console.log(`NEXTAUTH_URL: ${process.env.NEXTAUTH_URL}`)
console.log(`OKTA_DOMAIN: ${process.env.OKTA_DOMAIN}`)
console.log(`AUTH0_DOMAIN: ${process.env.AUTH0_DOMAIN}`)

module.exports = withHashicorp({
  defaultLayout: true,
  transpileModules: ['is-absolute-url', '@hashicorp/react-mega-nav'],
  mdx: { resolveIncludes: path.join(__dirname, 'pages/partials') },
})({
  experimental: { modern: true },
  env: {
    HASHI_ENV: process.env.HASHI_ENV || 'development',
    SEGMENT_WRITE_KEY: 'xxx',
    BUGSNAG_CLIENT_KEY: 'xxx',
    BUGSNAG_SERVER_KEY: 'xxx',
    NEXT_PUBLIC_OKTA_DOMAIN: process.env.OKTA_DOMAIN,
    NEXT_PUBLIC_AUTH0_DOMAIN: process.env.AUTH0_DOMAIN,
  },
})
