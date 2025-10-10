/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Example redirect:
 *
 * {
 *   source: '/vault/docs/some/path',
 *   destination: '/vault/docs/some/other/path',
 *   permanent: true
 * }
 *
 */

module.exports = [
  {
    source: '/boundary/docs/overview/what-is-boundary',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/what-is-boundary',
    destination: '/boundary/docs/:version/overview/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/index',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/roadmap',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/community',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/use-cases',
    destination: '/boundary/docs/overview/use-cases',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:10)\\.x)/overview/use-cases',
    destination: '/boundary/docs/:version/use-cases',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/other-software',
    destination: '/boundary/docs/overview/use-cases',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/zero-trust',
    destination: '/boundary/docs/overview/zero-trust',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/overview/zero-trust',
    destination: '/boundary/docs/:version/overview/vs/zero-trust',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/bastion-hosts',
    destination: '/boundary/docs/overview/bastion-hosts',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/overview/bastion-hosts',
    destination: '/boundary/docs/:version/overview/vs/bastion-hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/vpn',
    destination: '/boundary/docs/overview/vpn',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/overview/vpn',
    destination: '/boundary/docs/:version/overview/vs/vpn',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/pam',
    destination: '/boundary/docs/overview/pam',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/overview/pam',
    destination: '/boundary/docs/:version/overview/vs/pam',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/sdp',
    destination: '/boundary/docs/overview/sdp',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/overview/sdp',
    destination: '/boundary/docs/:version/overview/vs/sdp',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/secrets-management',
    destination: '/boundary/docs/overview/secrets-management',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:11|12|13|14|15|16|17|18)\\.x)/overview/secrets-management',
    destination: '/boundary/docs/:version/overview/vs/secrets-management',
    permanent: true,
  },
  {
    source: '/boundary/docs/troubleshoot/faq',
    destination: '/boundary/docs/overview/faq',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:12|13|14|15|16|17|18)\\.x)/overview/faq',
    destination: '/boundary/docs/:version/troubleshoot/faq',
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
    source: '/boundary/docs/oss/installing/dev-mode',
    destination: '/boundary/docs/getting-started/dev-mode',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/getting-started/dev-mode',
    destination: '/boundary/docs/:version/oss/installing/dev-mode',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/getting-started/dev-mode',
    destination: '/boundary/docs/:version/getting-started/dev-mode/dev-mode',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/run-and-login',
    destination: '/boundary/docs/getting-started/dev-mode/run-and-login',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/getting-started/dev-mode/run-and-login',
    destination: '/boundary/docs/:version/oss/installing/run-and-login',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/connect-to-dev-target',
    destination:
      '/boundary/docs/getting-started/dev-mode/connect-to-dev-target',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/getting-started/dev-mode/connect-to-dev-target',
    destination: '/boundary/docs/:version/oss/installing/connect-to-dev-target',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/architecture/:slug*',
    destination: '/boundary/docs/:version/architecture/:slug*',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/system-requirements',
    destination: '/boundary/docs/architecture/system-requirements',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14)\\.x)/architecture/system-requirements',
    destination: '/boundary/docs/:version/install-boundary/system-requirements',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/system-requirements',
    destination: '/boundary/docs/:version/architecture/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/architecture/system-requirements',
    destination: '/boundary/docs/architecture/system-requirements',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/architecture/system-requirements',
    destination:
      '/boundary/docs/:version/install-boundary/architecture/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/postgres',
    destination: '/boundary/docs/architecture/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/postgres',
    destination: '/boundary/docs/architecture/system-requirements',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/architecture/recommended-architecture',
    destination: '/boundary/docs/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/architecture/recommended-architecture',
    destination:
      '/boundary/docs/:version/install-boundary/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/reference-architectures',
    destination: '/boundary/docs/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/architecture/recommended-architecture',
    destination:
      '/boundary/docs/:version/oss/installing/reference-architectures',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/recommended-architecture',
    destination: '/boundary/docs/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14)\\.x)/architecture/recommended-architecture',
    destination:
      '/boundary/docs/:version/install-boundary/recommended-architecture',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/recommended-architecture',
    destination:
      '/boundary/docs/:version/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/architecture/fault-tolerance',
    destination: '/boundary/docs/architecture/fault-tolerance',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/architecture/fault-tolerance',
    destination:
      '/boundary/docs/:version/install-boundary/architecture/fault-tolerance',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/fault-tolerance',
    destination: '/boundary/docs/architecture/fault-tolerance',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14)\\.x)/architecture/fault-tolerance',
    destination: '/boundary/docs/:version/install-boundary/fault-tolerance',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/fault-tolerance',
    destination: '/boundary/docs/:version/architecture/fault-tolerance',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/architecture/high-availability',
    destination: '/boundary/docs/architecture/high-availability',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/architecture/high-availability',
    destination:
      '/boundary/docs/:version/install-boundary/architecture/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/high-availability',
    destination: '/boundary/docs/architecture/high-availability',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/architecture/high-availability',
    destination: '/boundary/docs/:version/oss/installing/high-availability',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8)\\.x)/architecture/high-availability',
    destination: '/boundary/docs/:version/installing/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/high-availability',
    destination: '/boundary/docs/architecture/high-availability',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14)\\.x)/architecture/high-availability',
    destination: '/boundary/docs/:version/install-boundary/high-availability',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/high-availability',
    destination: '/boundary/docs/:version/architecture/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary',
    destination: '/boundary/docs/deploy/self-managed',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/deploy/self-managed',
    destination: '/boundary/docs/:version/install-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary',
    destination: '/boundary/docs/:version/deploy/self-managed',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/install',
    destination: '/boundary/docs/deploy/self-managed/install',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17)\\.x)/deploy/self-managed/install',
    destination: '/boundary/docs/:version/install-boundary/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/install',
    destination: '/boundary/docs/:version/deploy/self-managed/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/deploy',
    destination: '/boundary/docs/deploy/self-managed/install',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:18)\\.x)/deploy/self-managed/install',
    destination: '/boundary/docs/:version/install-boundary/deploy',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/deploy',
    destination: '/boundary/docs/:version/deploy/self-managed/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/deploy',
    destination: '/boundary/docs/deploy/self-managed/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/configure-controllers',
    destination: '/boundary/docs/deploy/self-managed/configure-controllers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/deploy/self-managed/configure-controllers',
    destination:
      '/boundary/docs/:version/install-boundary/configure-controllers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/configure-controllers',
    destination:
      '/boundary/docs/:version/deploy/self-managed/configure-controllers',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/configure-workers',
    destination: '/boundary/docs/deploy/self-managed/deploy-workers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/deploy/self-managed/deploy-workers',
    destination: '/boundary/docs/:version/install-boundary/configure-workers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/configure-workers',
    destination: '/boundary/docs/:version/deploy/self-managed/deploy-workers',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/initialize',
    destination: '/boundary/docs/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/self-managed/initialize',
    destination: '/boundary/docs/:version/install-boundary/initialize',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/initialize',
    destination: '/boundary/docs/:version/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/no-gen-resources',
    destination: '/boundary/docs/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/deploy/self-managed/initialize',
    destination: '/boundary/docs/:version/oss/installing/no-gen-resources',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/no-gen-resources',
    destination: '/boundary/docs/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14)\\.x)/deploy/self-managed/initialize',
    destination: '/boundary/docs/:version/install-boundary/no-gen-resources',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/no-gen-resources',
    destination: '/boundary/docs/:version/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8)\\.x)/deploy/self-managed/initialize',
    destination: '/boundary/docs/:version/installing/no-gen-resources',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/install-clients',
    destination: '/boundary/docs/deploy/self-managed/install-clients',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:18)\\.x)/deploy/self-managed/install-clients',
    destination: '/boundary/docs/:version/install-boundary/install-clients',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/install-clients',
    destination: '/boundary/docs/:version/deploy/self-managed/install-clients',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/install-clients',
    destination: '/boundary/docs/deploy/self-managed/install-clients',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/systemd',
    destination: '/boundary/docs/deploy/self-managed/systemd',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/systemd',
    destination: '/boundary/docs/deploy/self-managed/systemd',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/systemd',
    destination: '/boundary/docs/deploy/self-managed/systemd',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing',
    destination: '/boundary/docs/deploy',
    permanent: true,
  },
  {
    source: '/boundary/docs/getting-started/connect-to-target',
    destination: '/boundary/docs/hcp/get-started/connect-to-target',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/hcp/get-started/connect-to-target',
    destination: '/boundary/docs/:version/getting-started/connect-to-target',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8)\\.x)/targets/connections',
    destination: '/boundary/docs/:version/getting-started/connect-to-target',
    permanent: true,
  },
  {
    source: '/boundary/docs/getting-started/deploy-and-login',
    destination: '/boundary/docs/hcp/get-started/deploy-and-login',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/hcp/get-started/deploy-and-login',
    destination: '/boundary/docs/:version/getting-started/deploy-and-login',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns',
    destination: '/boundary/docs/deploy/terraform-patterns',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:19)\\.x)/install-boundary/terraform-patterns/:slug*',
    destination: '/boundary/docs/:version/deploy/terraform-patterns/:slug*',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns',
    destination: '/boundary/docs/:version/install-boundary/terraform-patterns',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-credentials-and-credential-stores',
    destination:
      '/boundary/docs/deploy/terraform-patterns/terraform-credentials-and-credential-stores',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns/terraform-credentials-and-credential-stores',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-credentials-and-credential-stores',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-groups-and-rbac',
    destination:
      '/boundary/docs/deploy/terraform-patterns/terraform-groups-and-rbac',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns/terraform-groups-and-rbac',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-groups-and-rbac',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-hosts-and-host-management',
    destination:
      '/boundary/docs/deploy/terraform-patterns/terraform-hosts-and-host-management',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns/terraform-hosts-and-host-management',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-hosts-and-host-management',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-scopes',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-scopes',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns/terraform-scopes',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-scopes',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-session-recording',
    destination:
      '/boundary/docs/deploy/terraform-patterns/terraform-session-recording',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns/terraform-session-recording',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-session-recording',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-targets',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-targets',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-pattern/terraform-targets',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-targets',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/install-boundary/terraform-patterns/terraform-users-and-auth-methods',
    destination:
      '/boundary/docs/deploy/terraform-patterns/terraform-users-and-auth-methods',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/deploy/terraform-patterns/terraform-users-and-auth-methods',
    destination:
      '/boundary/docs/:version/install-boundary/terraform-patterns/terraform-users-and-auth-methods',
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
    source: '/boundary/docs/concepts/security/data-encryption',
    destination: '/boundary/docs/secure/encryption/data-encryption',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/secure/encryption/data-encryption',
    destination: '/boundary/docs/:version/concepts/security/data-encryption',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security',
    destination: '/boundary/docs/secure/encryption/data-encryption',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/connections-tls',
    destination: '/boundary/docs/secure/encryption/connections-tls',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/secure/encryption/connections-tls',
    destination: '/boundary/docs/:version/concepts/security/connections-tls',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations',
    destination: '/boundary/docs/monitor',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/monitor',
    destination: '/boundary/docs/:version/oss/operations',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations',
    destination: '/boundary/docs/monitor',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/monitor',
    destination: '/boundary/docs/:version/operations',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/operations',
    destination: '/boundary/docs/:version/monitor',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/listener',
    destination: '/boundary/docs/monitor/listeners',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/listeners',
    destination: '/boundary/docs/:version/configuration/listener',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/listener/tcp',
    destination: '/boundary/docs/monitor/listeners/tcp',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/listeners/tcp',
    destination: '/boundary/docs/:version/configuration/listener/tcp',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/listener/unix',
    destination: '/boundary/docs/monitor/listeners/unix',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/listeners/unix',
    destination: '/boundary/docs/:version/configuration/listener/unix',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations/metrics',
    destination: '/boundary/docs/monitor/metrics',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/monitor/metrics',
    destination: '/boundary/docs/:version/oss/operations/metrics',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations/metrics',
    destination: '/boundary/docs/monitor/metrics',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/operations/metrics',
    destination: '/boundary/docs/:version/monitor/metrics',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:8|13|14|15|16|17|18)\\.x)/monitor/metrics',
    destination: '/boundary/docs/:version/operations/metrics',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations/health',
    destination: '/boundary/docs/monitor/health',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:8|13|14|15|16|17|18)\\.x)/monitor/health',
    destination: '/boundary/docs/:version/operations/health',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/operations/health',
    destination: '/boundary/docs/:version/monitor/health',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations/health',
    destination: '/boundary/docs/monitor/health',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:9|10|11|12)\\.x)/monitor/health',
    destination: '/boundary/docs/:version/oss/operations/health',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/events',
    destination: '/boundary/docs/monitor/events/events',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:10|11|12|13|14|15|16|17|18)\\.x)/monitor/events/events',
    destination: '/boundary/docs/:version/configuration/events',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:5|6|7|8|9)\\.x)/monitor/events/events',
    destination: '/boundary/docs/:version/configuration/events/overview',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/events',
    destination: '/boundary/docs/monitor/events/filter-events',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/events/filter-events',
    destination: '/boundary/docs/:version/concepts/filtering/events',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/events/common',
    destination: '/boundary/docs/monitor/events/common',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/events/common',
    destination: '/boundary/docs/:version/configuration/events/common',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/events/file',
    destination: '/boundary/docs/monitor/events/file',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/events/file',
    destination: '/boundary/docs/:version/configuration/events/file',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/events/stderr',
    destination: '/boundary/docs/monitor/events/stderr',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/monitor/events/stderr',
    destination: '/boundary/docs/:version/configuration/events/stderr',
    permanent: true,
  },
  {
    source: '/boundary/docs/release-notes',
    destination: '/boundary/docs',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker',
    destination: '/boundary/docs/workers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|10|11|12|13|14|15|16|17|18)\\.x)/workers',
    destination: '/boundary/docs/:version/configuration/worker',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:9)\\.x)/workers',
    destination: '/boundary/docs/:version/configuration/worker/overview',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/worker-configuration',
    destination: '/boundary/docs/workers/registration',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/workers/registration',
    destination:
      '/boundary/docs/:version/configuration/worker/worker-configuration',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/kms-worker',
    destination: '/boundary/docs/workers/registration',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/pki-worker',
    destination: '/boundary/docs/workers/registration',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/multi-hop',
    destination: '/boundary/docs/workers/multi-hop',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/workers/multi-hop',
    destination:
      '/boundary/docs/:version/concepts/connection-workflows/multi-hop',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/worker-tags',
    destination: '/boundary/docs/workers/worker-tags',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/workers/worker-tags',
    destination: '/boundary/docs/:version/concepts/filtering/worker-tags',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/service-discovery',
    destination: '/boundary/docs/hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:8|9|10|11|12)\\.x)/hosts',
    destination: '/boundary/docs/:version/concepts/service-discovery',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery',
    destination: '/boundary/docs/hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/hosts',
    destination: '/boundary/docs/:version/concepts/host-discovery',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/aws',
    destination: '/boundary/docs/hosts/aws',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/hosts/aws',
    destination: '/boundary/docs/:version/concepts/host-discovery/aws',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/azure',
    destination: '/boundary/docs/hosts/azure',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/hosts/azure',
    destination: '/boundary/docs/:version/concepts/host-discovery/azure',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/gcp',
    destination: '/boundary/docs/hosts/gcp',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases',
    destination: '/boundary/docs/targets/configuration',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:18)\\.x)/targets/configuration',
    destination: '/boundary/docs/:version/configuration/target-aliases',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases/connect-target-alias',
    destination: '/boundary/docs/targets/connections/connect-target-alias',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:18)\\.x)/targets/connections/connect-target-alias',
    destination:
      '/boundary/docs/:version/configuration/target-aliases/connect-target-alias',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases/create-target-alias',
    destination: '/boundary/docs/targets/configuration/create-target-alias',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:18)\\.x)/targets/configuration/create-target-alias',
    destination:
      '/boundary/docs/:version/configuration/target-aliases/create-target-alias',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases/transparent-sessions',
    destination:
      '/boundary/docs/targets/configuration/configure-transparent-sessions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:18)\\.x)/targets/configuration/configure-transparent-sessions',
    destination:
      '/boundary/docs/:version/configuration/target-aliases/transparent-sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows',
    destination: '/boundary/docs/targets/connections',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/targets/connections',
    destination: '/boundary/docs/:version/concepts/connection-workflows',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/connect-helpers',
    destination: '/boundary/docs/targets/connections/connect-helpers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/targets/connections/connect-helpers',
    destination:
      '/boundary/docs/:version/concepts/connection-workflows/connect-helpers',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/exec-flag',
    destination: '/boundary/docs/targets/connections/exec-flag',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/targets/connections/exec-flag',
    destination:
      '/boundary/docs/:version/concepts/connection-workflows/exec-flag',
    permanent: true,
  },
  {
    source: '/boundary/docs/common-workflows/workflow-ssh-proxycommand',
    destination: '/boundary/docs/targets/connections/workflow-ssh-proxycommand',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/concepts/connection-workflows/workflow-ssh-proxycommand',
    destination: '/boundary/docs/targets/connections/workflow-ssh-proxycommand',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/targets/connections/workflow-ssh-proxycommand',
    destination:
      '/boundary/docs/:version/concepts/connection-workflows/workflow-ssh-proxycommand',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/credential-management',
    destination: '/boundary/docs/credentials',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/credentials',
    destination: '/boundary/docs/:version/configuration/credential-management',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/credential-management/configure-credential-brokering',
    destination: '/boundary/docs/credentials/configure-credential-brokering',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/credentials/configure-credential-brokering',
    destination:
      '/boundary/docs/:version/configuration/credential-management/configure-credential-brokering',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/credential-management/configure-credential-injection',
    destination: '/boundary/docs/credentials/configure-credential-injection',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/credentials/configure-credential-injection',
    destination:
      '/boundary/docs/:version/configuration/credential-management/configure-credential-injection',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/credential-management/static-cred-boundary',
    destination: '/boundary/docs/credentials/static-cred-boundary',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/credentials/static-cred-boundary',
    destination:
      '/boundary/docs/:version/configuration/credential-management/static-cred-boundary',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/credential-management/static-cred-vault',
    destination: '/boundary/docs/credentials/static-cred-vault',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/credentials/static-cred-vault',
    destination:
      '/boundary/docs/:version/configuration/credential-management/static-cred-vault',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/session-recording',
    destination: '/boundary/docs/session-recording',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/session-recording',
    destination: '/boundary/docs/:version/configuration/session-recording',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations/session-recordings',
    destination: '/boundary/docs/session-recording',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/configure-worker-storage',
    destination:
      '/boundary/docs/session-recording/configuration/configure-worker-storage',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:16|17|18)\\.x)/session-recording/configuration/configure-worker-storage',
    destination:
      '/boundary/docs/:version/configuration/session-recording/configure-worker-storage',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15)\\.x)/session-recording/configuration/configure-worker-storage',
    destination:
      '/boundary/docs/:version/configuration/session-recording/create-storage-bucket',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/session-recording/storage-providers',
    destination:
      '/boundary/docs/session-recording/configuration/storage-providers',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/storage-providers/configure-s3',
    destination:
      '/boundary/docs/session-recording/configuration/storage-providers/configure-s3',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:16|17|18)\\.x)/session-recording/configuration/storage-providers/configure-s3',
    destination:
      '/boundary/docs/:version/configuration/session-recording/storage-providers/configure-s3',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/storage-providers/configure-minio',
    destination:
      '/boundary/docs/session-recording/configuration/storage-providers/configure-minio',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:16|17|18)\\.x)/session-recording/configuration/storage-providers/configure-minio',
    destination:
      '/boundary/docs/:version/configuration/session-recording/storage-providers/configure-minio',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/storage-providers/configure-s3-compliant',
    destination:
      '/boundary/docs/session-recording/configuration/storage-providers/configure-s3-compliant',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:17|18)\\.x)/session-recording/configuration/storage-providers/configure-s3-compliant',
    destination:
      '/boundary/docs/:version/configuration/session-recording/storage-providers/configure-s3-compliant',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/create-storage-bucket',
    destination:
      '/boundary/docs/session-recording/configuration/create-storage-bucket',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/session-recording/configuration/create-storage-bucket',
    destination:
      '/boundary/docs/:version/configuration/session-recording/create-storage-bucket',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/enable-session-recording',
    destination:
      '/boundary/docs/session-recording/configuration/enable-session-recording',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/session-recording/configuration/enable-session-recording',
    destination:
      '/boundary/docs/:version/configuration/session-recording/enable-session-recording',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/operations/session-recordings/manage-recorded-sessions',
    destination:
      '/boundary/docs/session-recording/configuration/manage-recorded-sessions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/session-recording/configuration/manage-recorded-sessions',
    destination:
      '/boundary/docs/:version/operations/session-recordings/manage-recorded-sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/troubleshoot/troubleshoot-recorded-sessions',
    destination:
      '/boundary/docs/session-recording/configuration/troubleshoot-recorded-sessions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/session-recording/configuration/troubleshoot-recorded-sessions',
    destination:
      '/boundary/docs/:version/troubleshoot/troubleshoot-recorded-sessions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/configure-storage-policy',
    destination:
      '/boundary/docs/session-recording/compliance/configure-storage-policy',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/session-recording/compliance/configure-storage-policy',
    destination:
      '/boundary/docs/:version/configuration/session-recording/configure-storage-policy',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/session-recording/update-storage-policy',
    destination:
      '/boundary/docs/session-recording/compliance/update-storage-policy',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/session-recording/compliance/update-storage-policy',
    destination:
      '/boundary/docs/:version/configuration/session-recording/update-storage-policy',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations/session-recordings/validate-data-store',
    destination:
      '/boundary/docs/session-recording/compliance/validate-data-store',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/session-recording/compliance/validate-data-store',
    destination:
      '/boundary/docs/:version/operations/session-recordings/validate-data-store',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/operations/session-recordings/validate-session-recordings',
    destination:
      '/boundary/docs/session-recording/compliance/validate-session-recordings',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:14|15|16|17|18)\\.x)/session-recording/compliance/validate-session-recordings',
    destination:
      '/boundary/docs/:version/operations/session-recordings/validate-session-recordings',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/identity-access-management',
    destination: '/boundary/docs/rbac',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:17|18)\\.x)/rbac',
    destination:
      '/boundary/docs/:version/configuration/identity-access-management',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/permissions',
    destination: '/boundary/docs/rbac',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|1|14|15|16)\\.x)/rbac',
    destination: '/boundary/docs/:version/concepts/security/permissions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/concepts/security/permissions/assignable-permissions',
    destination: '/boundary/docs/rbac/assignable-permissions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:8|9|10|11|12|1|14|15|16)\\.x)/rbac/assignable-permissions',
    destination:
      '/boundary/docs/:version/concepts/security/permissions/assignable-permissions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/identity-access-management/assignable-permissions',
    destination: '/boundary/docs/rbac/assignable-permissions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:17|18)\\.x)/rbac/assignable-permissions',
    destination:
      '/boundary/docs/:version/configuration/identity-access-management/assignable-permissions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/concepts/security/permissions/permission-grant-formats',
    destination: '/boundary/docs/rbac/permission-grant-formats',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:8|9|10|11|12|1|14|15|16)\\.x)/rbac/permission-grant-formats',
    destination:
      '/boundary/docs/:version/concepts/security/permissions/permission-grant-formats',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/identity-access-management/permission-grant-formats',
    destination: '/boundary/docs/rbac/permission-grant-formats',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:17|18)\\.x)/rbac/permission-grant-formats',
    destination:
      '/boundary/docs/:version/configuration/identity-access-management/permission-grant-formats',
    permanent: true,
  },
  {
    source: '/boundary/docs/common-workflows/manage-roles',
    destination: '/boundary/docs/rbac/manage-roles',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|1|14|15|16|17|18)\\.x)/rbac/manage-roles',
    destination: '/boundary/docs/:version/common-workflows/manage-roles',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/permissions/resource-table',
    destination: '/boundary/docs/rbac/resource-table',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:8|9|10|11|12|1|14|15|16)\\.x)/rbac/resource-table',
    destination:
      '/boundary/docs/:version/concepts/security/permissions/resource-table',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/identity-access-management/resource-table',
    destination: '/boundary/docs/rbac/resource-table',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:17|18)\\.x)/rbac/resource-table',
    destination:
      '/boundary/docs/:version/configuration/identity-access-management/resource-table',
    permanent: true,
  },
  {
    source: '/boundary/docs/common-workflows/manage-users-groups',
    destination: '/boundary/docs/rbac/users/manage-users-groups',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|1|14|15|16|17|18)\\.x)/rbac/users/manage-users-groups',
    destination: '/boundary/docs/:version/common-workflows/manage-users-groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/oidc-managed-groups',
    destination: '/boundary/docs/rbac/users/managed-groups',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:4|5|6|7|8|9|10|11|12|13|14|15)\\.x)/rbac/users/managed-groups',
    destination:
      '/boundary/docs/:version/concepts/filtering/oidc-managed-groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/managed-groups',
    destination: '/boundary/docs/rbac/users/managed-groups',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:16|17|18)\\.x)/rbac/users/managed-groups',
    destination: '/boundary/docs/:version/concepts/filtering/managed-groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/integrations',
    destination: '/boundary/docs',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/integrations',
    destination: '/boundary/docs/:version',
    permanent: true,
  },
  {
    source: '/boundary/docs/integrations/vault',
    destination: '/boundary/docs/vault',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/vault',
    destination: '/boundary/docs/:version/integrations/vault',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:19)\\.x)/integrations/vault',
    destination: '/boundary/docs/:version/vault',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/go-sdk',
    destination: '/boundary/docs/go-sdk',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/go-sdk',
    destination: '/boundary/docs/:version/api-clients/go-sdk',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/client-agent',
    destination: '/boundary/docs/client-agent',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:18)\\.x)/client-agent',
    destination: '/boundary/docs/:version/api-clients/client-agent',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/client-cache',
    destination: '/boundary/docs/client-cache',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/client-cache',
    destination: '/boundary/docs/:version/api-clients/client-cache',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/api',
    destination: '/boundary/docs/api',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/api',
    destination: '/boundary/docs/:version/api-clients/api',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/api/pagination',
    destination: '/boundary/docs/api/pagination',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/api/pagination',
    destination: '/boundary/docs/:version/api-clients/api/pagination',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/api/rate-limiting',
    destination: '/boundary/docs/api/rate-limiting',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/api/rate-limiting',
    destination: '/boundary/docs/:version/api-clients/api/rate-limiting',
    permanent: true,
  },
  {
    source: '/boundary/docs/api-clients/cli',
    destination: '/boundary/docs/commands/',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12)\\.x)/commands',
    destination: '/boundary/docs/:version/api-clients/cli',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model',
    destination: '/boundary/docs/domain-model',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model',
    destination: '/boundary/docs/:version/concepts/domain-model',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/accounts',
    destination: '/boundary/docs/domain-model/accounts',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/accounts',
    destination: '/boundary/docs/:version/concepts/domain-model/accounts',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/aliases',
    destination: '/boundary/docs/domain-model/aliases',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:16|17|18)\\.x)/domain-model/aliases',
    destination: '/boundary/docs/:version/concepts/domain-model/aliases',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/auth-methods',
    destination: '/boundary/docs/domain-model/auth-methods',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/auth-methods',
    destination: '/boundary/docs/:version/concepts/domain-model/auth-methods',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/credentials',
    destination: '/boundary/docs/domain-model/credentials',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/credentials',
    destination: '/boundary/docs/:version/concepts/domain-model/credentials',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/credential-libraries',
    destination: '/boundary/docs/domain-model/credential-libraries',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/credential-libraries',
    destination:
      '/boundary/docs/:version/concepts/domain-model/credential-libraries',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/credential-stores',
    destination: '/boundary/docs/domain-model/credential-stores',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/credential-stores',
    destination:
      '/boundary/docs/:version/concepts/domain-model/credential-stores',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/groups',
    destination: '/boundary/docs/domain-model/groups',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/groups',
    destination: '/boundary/docs/:version/concepts/domain-model/groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/hosts',
    destination: '/boundary/docs/domain-model/hosts',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/hosts',
    destination: '/boundary/docs/:version/concepts/domain-model/hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/host-catalogs',
    destination: '/boundary/docs/domain-model/host-catalogs',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/host-catalogs',
    destination: '/boundary/docs/:version/concepts/domain-model/host-catalogs',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/host-sets',
    destination: '/boundary/docs/domain-model/host-sets',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/host-sets',
    destination: '/boundary/docs/:version/concepts/domain-model/host-sets',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/managed-groups',
    destination: '/boundary/docs/domain-model/managed-groups',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/managed-groups',
    destination: '/boundary/docs/:version/concepts/domain-model/managed-groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/roles',
    destination: '/boundary/docs/domain-model/roles',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/roles',
    destination: '/boundary/docs/:version/concepts/domain-model/roles',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/scopes',
    destination: '/boundary/docs/domain-model/scopes',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/scopes',
    destination: '/boundary/docs/:version/concepts/domain-model/scopes',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/sessions',
    destination: '/boundary/docs/domain-model/sessions',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/sessions',
    destination: '/boundary/docs/:version/concepts/domain-model/sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/session-connections',
    destination: '/boundary/docs/domain-model/session-connections',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/session-connections',
    destination:
      '/boundary/docs/:version/concepts/domain-model/session-connections',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/session-recordings',
    destination: '/boundary/docs/domain-model/session-recordings',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/domain-model/session-recordings',
    destination:
      '/boundary/docs/:version/concepts/domain-model/session-recordings',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/storage-buckets',
    destination: '/boundary/docs/domain-model/storage-buckets',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:13|14|15|16|17|18)\\.x)/domain-model/storage-buckets',
    destination:
      '/boundary/docs/:version/concepts/domain-model/storage-buckets',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/storage-policy',
    destination: '/boundary/docs/domain-model/storage-policy',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:15|16|17|18)\\.x)/domain-model/storage-policy',
    destination: '/boundary/docs/:version/concepts/domain-model/storage-policy',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/targets',
    destination: '/boundary/docs/domain-model/targets',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/targets',
    destination: '/boundary/docs/:version/concepts/domain-model/targets',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/users',
    destination: '/boundary/docs/domain-model/users',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/domain-model/users',
    destination: '/boundary/docs/:version/concepts/domain-model/users',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering',
    destination: '/boundary/docs/filtering',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/:version(v0\\.(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\\.x)/filtering',
    destination: '/boundary/docs/:version/concepts/filtering',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/resource-listing',
    destination: '/boundary/docs/filtering',
    permanent: true,
  },
  {
    source: '/boundary/docs/troubleshoot/common-errors',
    destination: '/boundary/docs/errors',
    permanent: true,
  },
  {
    source: '/boundary/docs/:version(v0\\.(?:12|13|14|15|16|17|18)\\.x)/errors',
    destination: '/boundary/docs/:version/troubleshoot/common-errors',
    permanent: true,
  },
  {
    source:
      '/boundary/docs/configuration/target-aliases/interoperability-matrix',
    destination: '/boundary/docs/interoperability-matrix/index',
    permanent: true,
  },
]
