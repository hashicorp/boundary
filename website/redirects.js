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
    source: '/boundary/docs/overview/what-is-boundary',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/use-cases',
    destination: '/boundary/docs/overview/use-cases',
    permanent: true,
  },
  {
    source: '/boundary/docs/roadmap',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/bastion-hosts',
    destination: '/boundary/docs/overview/bastion-hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/other-software',
    destination: '/boundary/docs/overview/use-cases',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/pam',
    destination: '/boundary/docs/overview/pam',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/sdp',
    destination: '/boundary/docs/overview/sdp',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/secrets-management',
    destination: '/boundary/docs/overview/secrets-management',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/vpn',
    destination: '/boundary/docs/overview/vpn',
    permanent: true,
  },
  {
    source: '/boundary/docs/overview/vs/zero-trust',
    destination: '/boundary/dos/overview/zero-trust',
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
    source: '/boundary/docs/install-boundary/architecture/fault-tolerance',
    destination: '/boundary/docs/architecture/fault-tolerance',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/architecture/high-availability',
    destination: '/boundary/docs/architecture/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/architecture/recommended-architecture',
    destination: '/boundary/docs/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/architecture/system-requirements',
    destination: '/boundary/docs/architecture/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/index',
    destination: '/boundary/docs/deploy/self-managed/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/index',
    destination: '/boundary/docs/deploy/self-managed/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/configure-controllers',
    destination: '/boundary/docs/deploy/self-managed/configure-controllers',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/configure-controllers',
    destination: '/boundary/docs/deploy/self-managed/configure-controllers',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/configure-workers',
    destination: '/boundary/docs/deploy/self-managed/configure-workers',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/configure-workers',
    destination: '/boundary/docs/deploy/self-managed/configure-workers',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/deploy',
    destination: '/boundary/docs/deploy/self-managed/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/deploy',
    destination: '/boundary/docs/deploy/self-managed/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/initialize',
    destination: '/boundary/docs/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/self-managed/initialize',
    destination: '/boundary/docs/deploy/self-manaaged/initialize',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/install-clients',
    destination: '/boundary/docs/deploy/self-managed/install-clients',
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
    source: '/boundary/docs/install-boundary/terraform-patterns',
    destination: '/boundary/docs/deploy/terraform-patterns',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/index',
    destination: '/boundary/docs/deploy/terraform-patterns/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-credentials-and-credential-stores',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-credentials-and-credential-stores',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-groups-and-rbac',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-groups-and-rbac',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-hosts-and-host-management',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-hosts-and-host-management',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-scopes',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-scopes',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-session-recording',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-session-recording',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-targets',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-targets',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/terraform-patterns/terraform-users-and-auth-methods',
    destination: '/boundary/docs/deploy/terraform-patterns/terraform-users-and-auth-methods',
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
    destination: '/boundary/docs/getting-started/dev-mode/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/run-and-login',
    destination: '/boundary/docs/getting-started/dev-mode/run-and-login',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations/health',
    destination: '/boundary/docs/monitor/health',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations',
    destination: '/boundary/docs/monitor',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/operations/metrics',
    destination: '/boundary/docs/monitor/metrics',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/install',
    destination: '/boundary/docs/deploy/self-managed/install',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/fault-tolerance',
    destination: '/boundary/docs/architecture/fault-tolerance',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/high-availability',
    destination: '/boundary/docs/architecture/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/high-availability',
    destination: '/boundary/docs/architecture/high-availability',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing',
    destination: '/boundary/docs/deploy',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/no-gen-resources',
    destination: '/boundary/docs/deploy/self-managed/initialize',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/no-gen-resources',
    destination: '/boundary/docs/deploy/self-managed/initialize',
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
    source: '/boundary/docs/install-boundary/system-requirements',
    destination: '/boundary/docs/architecture/system-requirements',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/reference-architectures',
    destination: '/boundary/docs/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source: '/boundary/docs/install-boundary/recommended-architecture',
    destination: '/boundary/docs/architecture/recommended-architecture',
    permanent: true,
  },
  {
    source: '/boundary/docs/oss/installing/systemd',
    destination: '/boundary/docs/deploy/self-managed/systemd',
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
    source: '/boundary/docs/concepts/security/data-encryption',
    destination: '/boundary/docs/secure/encrypt/data-encryption',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/connections-tls',
    destination: '/boundary/docs/secure/encrypt/connections-tls',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/worker-tags',
    destination: '/boundary/docs/secure/worker-tags',
    permanent: true,
  },
  {
    source: '/boundary/docs/security/encryption/connections-tls',
    destination: '/boundary/docs/secure/encrypt/connections-tls',
    permanent: true,
  },
  {
    source: '/boundary/docs/security/encryption/data-encryption',
    destination: '/boundary/docs/secure/encrypt/data-encryption',
    permanent: true,
  },
  {
    source: '/boundary/docs/security/worker-tags',
    destination: '/boundary/docs/secure/worker-tags',
  },
  {
    source: '/boundary/docs/concepts/service-discovery',
    destination: '/boundary/docs/hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/operations/manage-recorded-sessions',
    destination: '/boundary/docs/session-recording/configuration/manage-recorded-sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/common-workflows/workflow-ssh-proxycommand',
    destination:
      '/boundary/docs/targets/connections/workflow-ssh-proxycommand',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker',
    destination: '/boundary/docs/workers',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/index',
    destination: '/boundary/docs/workers/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/worker-configuration',
    destination: '/boundary/docs/configure-workers/worker-configuration',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery',
    destination: '/boundary/docs/hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/index',
    destination: '/boundary/docs/hosts/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/aws',
    destination: '/boundary/docs/hosts/discovery/aws',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/azure',
    destination: '/boundary/docs/hosts/discovery/azure',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/host-discovery/gcp',
    destination: '/boundary/docs/hosts/discovery/gcp',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker-configuration',
    destination: '/boundary/docs/workers/configure-workers/registration',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases',
    destination: '/boundary/docs/targets/configuration',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases/index',
    destination: '/boundary/docs/targets/configuration/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases/connect-target-alias',
    destination: '/boundary/docs/targets/connections/connect-target-alias',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/target-aliases/create-target-alias',
    destination: '/boundary/docs/targets/configuration/create-target-alias',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows',
    destination: '/boundary/docs/targets/connections',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/index',
    destination: '/boundary/docs/targets/connections/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/connect-helpers',
    destination: '/boundary/docs/targets/connections/connect-helpers',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/exec-flag',
    destination: '/boundary/docs/targets/connections/exec-flag',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/multi-hop',
    destination: '/boundary/docs/targets/configuration/multi-hop',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/connection-workflows/workflow-ssh-proxycommand',
    destination: '/boundary/docs/targets/connections/workflow-ssh-proxycommand',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/credential-management',
    destination: '/boundary/docs/credentials',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/credential-management/index',
    destination: '/boundary/docs/credentials/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/credential-management/configure-credential-brokering',
    destination: '/boundary/docs/credentials/configure-credential-brokering',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/credential-management/configure-credential-injection',
    destination: '/boundary/docs/credentials/configure-credential-injection',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/credential-management/static-cred-boundary',
    destination: '/boundary/docs/credentials/static-cred-boundary',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/credential-management/static-cred-vault',
    destination: '/boundary/docs/credentials/static-cred-vault',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording',
    destination: '/boundary/docs/session-recording',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/index',
    destination: '/boundary/docs/session-recording/index',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/configure-worker-storage',
    destination: '/boundary/docs/session-recording/configuration/configure-worker-storage',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/create-storage-bucket',
    destination: '/boundary/docs/session-recording/configuration/create-storage-bucket',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/enable-session-recording',
    destination: '/boundary/docs/session-recording/configuration/enable-session-recording',
    permanent: true
  },
  {
    source: '/boundary/docs/monitor/session-recordings/manage-recorded-sessions',
    destination: '/boundary/docs/session-recording/configuration/manage-recorded-sessions',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/storage-providers',
    destination: '/boundary/docs/session-recording/configuration/storage-providers',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/storage-providers/configure-minio',
    destination: '/boundary/docs/session-recording/configuration/storage-providers/configure-minio',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/storage-providers/configure-s3-compliant',
    destination: '/boundary/docs/session-recording/configuration/storage-providers/configure-s3-compliant',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/storage-providers/configure-s3',
    destination: '/boundary/docs/session-recording/configuration/storage-providers/configure-s3',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/configure-storage-policy',
    destination: '/boundary/docs/session-recording/compliance/configure-storage-policy',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/session-recording/update-storage-policy',
    destination: '/boundary/docs/session-recording/compliance/update-storage-policy',
    permanent: true
  },
  {
    source: '/boundary/docs/monitor/session-recordings',
    destination: '/boundary/docs/session-recording',
    permanent: true
  },
  {
    source: '/boundary/docs/monitor/session-recordings/index',
    destination: '/boundary/docs/session-recording/index',
    permanent: true
  },
  {
    source: '/boundary/docs/monitor/session-recordings/validate-data-store',
    destination: '/boundary/docs/session-recording/compliance/validate-data-store',
    permanent: true
  },
  {
    source: '/boundary/docs/monitor/session-recordings/validate-session-recordings',
    destination: '/boundary/docs/session-recording/compliance/validate-session-recordings',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/identity-access-management/index',
    destination: '/boundary/docs/rbac/permissions/index',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/identity-access-management/assignable-permissions',
    destination: '/boundary/docs/rbac/permissions/assignable-permissions',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/identity-access-management/permission-grant-formats',
    destination: '/boundary/docs/rbac/permissions/permission-grant-formats',
    permanent: true
  },
  {
    source: '/boundary/docs/common-workflows/manage-roles',
    destination: '/boundary/docs/rbac/permissions/manage-roles',
    permanent: true
  },
  {
    source: '/boundary/docs/configuration/identity-access-management/resource-table',
    destination: '/boundary/docs/rbac/permissions/resource-table',
    permanent: true
  },
  {
    source: '/boundary/docs/common-workflows/manage-users-groups',
    destination: '/boundary/docs/rbac/users/manage-users-groups',
    permanent: true
  },
  {
    source: '/boundary/docs/concepts/filtering/managed-groups',
    destination: '/boundary/docs/rbac/users/managed-groups',
    permanent: true
  },
  {
    source: '/boundary/docs/integrations/vault',
    destination: '/boundary/docs/vault',
    permanent: true
  },
  {
    source: '/boundary/docs/integrations/vault/index',
    destination: '/boundary/docs/vault/index',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/go-sdk',
    destination: '/boundary/docs/go-sdk/index',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/client-agent',
    destination: '/boundary/docs/client-agent/index',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/client-cache',
    destination: '/boundary/docs/api/client-cache',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/api',
    destination: '/boundary/docs/api',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/api/index',
    destination: '/boundary/docs/api/index',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/api/pagination',
    destination: '/boundary/docs/api/pagination',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/api/rate-limiting',
    destination: '/boundary/docs/api/rate-limiting',
    permanent: true
  },
  {
    source: '/boundary/docs/api-clients/cli',
    destination: '/boundary/docs/commands/',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/index',
    destination: '/boundary/docs/what-is-boundary',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/service-discovery',
    destination: '/boundary/docs/concepts/host-discovery',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/oidc-managed-groups',
    destination: '/boundary/docs/concepts/filtering/managed-groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/kms-worker',
    destination: '/boundary/docs/configuration/worker/worker-configuration',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/worker/pki-worker',
    destination: '/boundary/docs/configuration/worker/worker-configuration',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/listener',
    destination: '/boundary/docs/monitor/listeners',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/listener/tcp',
    destination: '/boundary/docs/monitor/listeners/tcp',
    permanent: true,
  },
  {
    source: '/boundary/docs/configuration/listener/unix',
    destination: '/boundary/docs/monitor/listeners/unix',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/permissions/resource-table',
    destination: '/boundary/docs/configuration/identity-access-management/resource-table',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/permissions/assignable-permissions',
    destination: '/boundary/docs/configuration/identity-access-management/assignable-permisisons',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/permissions/permission-grant-formats',
    destination: '/boundary/docs/configuration/identity-access-management/permission-grant-formats',
    permanent: true,
  },
  {
    source: '/boundary/docs/target-aliases/transparent-sessions',
    destination: '/boundary/docs/targets/connections/transparent-sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/target-aliases/interoperability-matrix',
    destination: '/boundary/docs/interoperability-matrix/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security/permissions',
    destination: '/boundary/docs/configuration/identity-access-management',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model',
    destination: '/boundary/docs/domain-model',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/index',
    destination: '/boundary/docs/domain-model/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/accounts',
    destination: '/boundary/docs/domain-model/accounts',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/aliases',
    destination: '/boundary/docs/domain-model/aliases',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/auth-methods',
    destination: '/boundary/docs/domain-model/auth-methods',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/credential-libraries',
    destination: '/boundary/docs/domain-model/credential-libraries',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/credential-stores',
    destination: '/boundary/docs/domain-model/credential-stores',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/credentials',
    destination: '/boundary/docs/domain-model/credentials',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/groups',
    destination: '/boundary/docs/domain-model/groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/host-catalogs',
    destination: '/boundary/docs/domain-model/host-catalogs',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/host-sets',
    destination: '/boundary/docs/domain-model/host-sets',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/hosts',
    destination: '/boundary/docs/domain-model/hosts',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/managed-groups',
    destination: '/boundary/docs/domain-model/managed-groups',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/roles',
    destination: '/boundary/docs/domain-model/roles',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/scopes',
    destination: '/boundary/docs/domain-model/scopes',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/session-connections',
    destination: '/boundary/docs/domain-model/session-connections',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/session-recordings',
    destination: '/boundary/docs/domain-model/session-recordings',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/sessions',
    destination: '/boundary/docs/domain-model/sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/storage-buckets',
    destination: '/boundary/docs/domain-model/storage-buckets',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/storage-policy',
    destination: '/boundary/docs/domain-model/storage-policy',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/targets',
    destination: '/boundary/docs/domain-model/targets',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/domain-model/users',
    destination: '/boundary/docs/domain-model/users',
    permanent: true,
  },
  {
    source: '/boundary/docs/troubleshoot/faq',
    destination: '/boundary/docs/overview/faq',
    permanent: true,
  },
  {
    source: '/boundary/docs/troubleshoot/troubleshoot-recorded-sessions',
    destination: '/boundary/docs/session-recording/configuration/troubleshoot-recorded-sessions',
    permanent: true,
  },
  {
    source: '/boundary/docs/troubleshoot/common-errors',
    destination: '/boundary/docs/errors/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/security',
    destination: '/boundary/docs/secure/encrypt/data-encryption',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering',
    destination: '/boundary/docs/filtering',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/index',
    destination: '/boundary/docs/filtering/index',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/events',
    destination: '/boundary/docs/filtering/events',
    permanent: true,
  },
  {
    source: '/boundary/docs/concepts/filtering/resource-listing',
    destination: '/boundary/docs/filtering/resource-listing',
    permanent: true,
  },
  {
    source: '/boundary/docs/release-notes/index',
    destination: '/boundary/docs',
    permanent: true,
  },
  {
    source: '/boundary/docs/release-notes',
    destination: '/boundary/docs',
    permanent: true,
  },
]
