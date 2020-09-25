import nextAuthApiRoute from 'lib/next-auth-utils/config'

export default (req, res) =>
  nextAuthApiRoute(
    req,
    res
  )({
    environments: { production: ['Okta', 'Auth0'], preview: ['Okta', 'Auth0'] },
    pages: {
      error: '/signin-error', // Error code passed in query string as ?error=
    },
  })
