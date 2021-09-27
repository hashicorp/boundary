import BrandedCta from 'components/branded-cta'
import HomepageHero from 'components/homepage-hero'
import HowItWorks from 'components/how-it-works'
import SectionBreakCta from 'components/section-break-cta'
import ProductFeaturesList from '@hashicorp/react-product-features-list'
import UseCases from '@hashicorp/react-use-cases'

export default function HomePage() {
  return (
    <div className="p-home">
      <HomepageHero
        title="Simple and secure remote access"
        description="Access any system from anywhere based on user identity."
        links={[
          {
            title: 'Get Started',
            url:
              'https://learn.hashicorp.com/collections/boundary/getting-started',
            external: true,
          },
          {
            title: 'Boundary Desktop',
            url: '/downloads#desktop',
            linkType: 'inbound',
            theme: { variant: 'tertiary' },
          },
        ]}
        uiVideo={{
          url: 'https://www.datocms-assets.com/2885/1614100050-hero-ui.mp4',
          srcType: 'mp4',
          playbackRate: 2,
        }}
        cliVideo={{
          url: 'https://www.datocms-assets.com/2885/1614100038-hero-cli.mp4',
          srcType: 'mp4',
          aspectRatio: 0.62295082,
          playbackRate: 1,
        }}
        desktopVideo={{
          url:
            'https://www.datocms-assets.com/2885/1614100044-hero-desktop.mp4',
          srcType: 'mp4',
          aspectRatio: 0.59968354,
          playbackRate: 1,
        }}
      />

      <HowItWorks
        title="Secure access to hosts and services"
        description="Traditional approaches like SSH bastion hosts or VPNs require distributing and managing credentials, configuring network controls like firewalls, and exposing the private network. Boundary provides a secure way to access hosts and critical systems without having to manage credentials or expose your network, and is entirely open source."
        features={[
          {
            title: 'Authenticate',
            description:
              'Authenticate with any trusted identity provider you are already using. No need to distribute new credentials and manage them.',
            logos: [
              {
                alt: 'GitHub',
                url: require('./img/logos/github-gray.svg?url'),
              },
              {
                alt: 'AWS',
                url: require('./img/logos/aws-gray.svg?url'),
              },
              {
                alt: 'Microsoft Azure',
                url: require('./img/logos/azure-color.svg?url'),
              },
              {
                alt: 'Google Cloud Platform',
                url: require('./img/logos/gcp-color.svg?url'),
              },
              {
                alt: 'Okta',
                url: require('./img/logos/okta-color.svg?url'),
              },
              {
                alt: 'Ping',
                url: require('./img/logos/ping-color.svg?url'),
              },
              {
                alt: 'More integrations',
                url: require('./img/logos/more-gray.svg?url'),
              },
            ],
          },
          {
            title: 'Authorize',
            description:
              'Authorize access based on logical roles and services, instead of physical IP addresses. Manage dynamic infrastructure and integrate service registries so hosts and service catalogs are kept up-to-date.',
            logos: [
              {
                alt: 'Consul',
                url: require('./img/logos/consul-color.svg?url'),
              },
              {
                alt: 'AWS',
                url: require('./img/logos/aws-color.svg?url'),
              },
              {
                alt: 'Microsoft Azure',
                url: require('./img/logos/azure-color.svg?url'),
              },
              {
                alt: 'Terraform',
                url: require('./img/logos/terraform-color.svg?url'),
              },
              {
                alt: 'Google Cloud Platform',
                url: require('./img/logos/gcp-color.svg?url'),
              },
              {
                alt: 'Kubernetes',
                url: require('./img/logos/kubernetes-color.svg?url'),
              },
              {
                url: require('./img/logos/more-gray.svg?url'),
                alt: 'More integrations',
              },
            ],
          },
          {
            title: 'Access',
            description:
              'Automate credential injection to securely access services and hosts with HashiCorp Vault. Reduce risk of leaking credentials with dynamic secrets and just-in-time credentials.',
          },
        ]}
      />

      <div className="use-cases-section">
        <div className="g-grid-container">
          <h2 className="g-type-display-2">Use cases</h2>
          <UseCases
            items={[
              {
                title: 'Easily onboard and manage users',
                description:
                  'Use SSO to manage onboarding and off-boarding users.',
                image: {
                  url: require('./img/red-usecase-accessmgmt.png?url'),
                },
                link: {
                  title: 'Learn more',
                  url:
                    'https://learn.hashicorp.com/tutorials/boundary/getting-started-config',
                },
              },
              {
                title: 'Open and extensible remote access',
                description:
                  'Integrate with existing tooling and APIs to simplify access.',
                image: {
                  url: require('./img/red-usecase-accessprivileges.png?url'),
                },
                link: {
                  title: 'Learn more',
                  url:
                    'https://learn.hashicorp.com/tutorials/boundary/manage-users-groups',
                },
              },
              {
                title: 'Compliance without overhead',
                description:
                  'Provide session visibility that enables teams to stay compliant.',
                image: {
                  url: require('./img/red-usecase-sessionvisibility.png?url'),
                },
                link: {
                  title: 'Learn more',
                  url:
                    'https://learn.hashicorp.com/tutorials/boundary/manage-sessions',
                },
              },
            ]}
          />
        </div>
      </div>

      <div className="break-section">
        <SectionBreakCta
          heading="Have you tried Boundary?"
          content="Share your feedback for a chance to receive special swag."
          link={{
            text: 'Share your Boundary story',
            url: 'http://hashi.co/boundary-survey',
          }}
        />
      </div>

      <section className="features-section">
        <ProductFeaturesList
          heading="Boundary Features"
          features={[
            {
              title: 'Identity-based access',
              content:
                'Enables privileged sessions for users and applications based on user identity and role.',
              icon: require('./img/features/identity-based-access.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/getting-started-intro',
              },
            },
            {
              title: 'Session management',
              content:
                'Ensures access control regardless of user or operators’ infrastructure.',
              icon: require('./img/features/session-management.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/manage-sessions?in=boundary/common-workflows',
              },
            },
            {
              title: 'Platform agnostic',
              content:
                'One workflow for identity-based access across clouds, kubernetes clusters, and on-prem infrastructure.',
              icon: require('./img/features/platform-agnosticity.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url: '/docs/getting-started/connect-to-target',
              },
            },
            {
              title: 'Session visibility',
              content:
                'Visibility into session metrics, events, logs, and traces with the ability to export data to business intelligence and event monitoring tools.',
              icon: require('./img/features/session-visibility.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/manage-sessions?in=boundary/common-workflows',
              },
            },
            {
              title: 'Infrastructure as code',
              content:
                'Define policies and manage Boundary with an Infrastructure as Code approach. Terraform provider supports the full breadth of Boundary configurations.',
              icon: require('./img/features/config-as-code.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/getting-started-config',
              },
            },
            {
              title: 'Manage dynamic environments',
              content:
                'Secure access to dynamic systems and applications with automated controls.',
              icon: require('./img/features/managing-dynamic-environments.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url: '/docs/api-clients',
              },
            },
          ]}
        />
      </section>

      <BrandedCta
        heading="Ready to get started?"
        content="Boundary is an open source solution that automates a secure identity-based user access to hosts and services across environments."
        links={[
          {
            text: 'Get Started',
            url:
              'https://learn.hashicorp.com/collections/boundary/getting-started',
            type: 'outbound',
          },
          { text: 'Explore documentation', url: '/docs' },
        ]}
      />
    </div>
  )
}
