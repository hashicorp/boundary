/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

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
  {
    source: '/boundary/docs/getting-started/connect-to-target',
    destination: '/boundary/docs/hcp/get-started/connect-to-target',
    permanent: true,
  },
  {
    source: '/boundary/docs/getting-started/deploy-and-login',
    destination: '/boundary/docs/hcp/get-started/deploy-and-login',
    permanent: true,
  },
  {
    source: '/boundary/docs/getting-started/installing',
    destination: '/boundary/docs/getting-started',
    permanent: true,
  },
  {
    source: '/boundary/docs/getting-started/installing/production',
    destination: '/boundary/docs/getting-started',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/developing/building',
    destination: '/boundary/docs/developing/building',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/developing',
    destination: '/boundary/docs/developing',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/developing/ui',
    destination: '/boundary/docs/developing/ui',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/connect-to-dev-target',
    destination:
      '/boundary/docs/getting-started/dev-mode/connect-to-dev-target',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/dev-mode',
    destination: '/boundary/docs/getting-started/dev-mode/dev-mode',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/run-and-login',
    destination: '/boundary/docs/getting-started/dev-mode/run-and-login',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations/health',
    destination: '/boundary/docs/operations/health',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations',
    destination: '/boundary/docs/operations',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations/metrics',
    destination: '/boundary/docs/operations/metrics',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/high-availability',
    destination: '/boundary/docs/install-boundary/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing',
    destination: '/boundary/docs/install-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/no-gen-resources',
    destination: '/boundary/docs/install-boundary/no-gen-resources',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/postgres',
    destination: '/boundary/docs/install-boundary/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/postgres',
    destination: '/boundary/docs/install-boundary/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/reference-architectures',
    destination: '/boundary/docs/install-boundary/recommended-architecture',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/systemd',
    destination: '/boundary/docs/install-boundary/systemd',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/service-discovery',
    destination: '/boundary/docs/concepts/host-discovery',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations/manage-recorded-sessions',
    destination: '/boundary/docs/operations/session-recordings',
    permanent: true,
  },
  {
    source: '/boundary/docs/common-workflows/workflow-ssh-proxycommand',
    destination: '/boundary/docs/concepts/connection-workflows/workflow-ssh-proxycommand',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/cli',
    destination: '/boundary/docs/commands/',
  },
  {
    source: '/boundary/docs/concepts/service-discovery',
    destination: '/boundary/docs/concepts/host-discovery',
  }
]
