import BrandedCta from 'components/branded-cta'
import HomepageHero from 'components/homepage-hero'
import HowItWorks from 'components/how-it-works'
import HowBoundaryWorks from 'components/how-boundary-works'
import WhyBoundary from 'components/why-boundary'
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
            title: 'Explore tutorials',
            url:
              'https://learn.hashicorp.com/collections/boundary/getting-started',
            external: true,
          },
          {
            title: 'Download macOS Client',
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
          playbackRate: 1,
        }}
        desktopVideo={{
          url:
            'https://www.datocms-assets.com/2885/1614100044-hero-desktop.mp4',
          srcType: 'mp4',
          playbackRate: 1,
        }}
      />

      <HowItWorks
        title="Secure access to hosts and services"
        description={
          <>
            <p>
              In the shift to the cloud, organizations need secure access to
              targets beyond their own perimeter.
            </p>
            <p>
              Boundary provides a secure way to access hosts and critical
              systems without having to manage credentials or expose your
              network, and is entirely open source.
            </p>
          </>
        }
        features={[
          {
            title: 'Authenticate & authorize',
            description:
              'Authenticate with any trusted identity provider you are already using and authorize access based on granular, logical roles and services.',
            logos: [
              {
                alt: 'GitHub',
                url: require('./img/logos/github-black.svg?url'),
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
                url: require('./img/logos/custom.svg?url'),
              },
            ],
          },
          {
            title: 'Connect',
            description:
              'Manage dynamic infrastructure and integrate service registries so hosts and service catalogs are kept up-to-date.',
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

      <section className="why-boundary">
        <WhyBoundary
          heading="Why Boundary"
          items={[
            {
              icon: require('./img/icons/code-white.svg?url'),
              heading: 'On-demand identity-based access to infrastructure',
              description:
                'Securely connect trusted identities to logical services without having to create or store credentials or access.',
            },
            {
              icon: require('./img/icons/layers-white.svg?url'),
              heading: 'Scale access management in dynamic environments',
              description:
                'Scale access management by defining access controls around logical services instead of IP-based access policies.',
            },
            {
              icon: require('./img/icons/refresh-white.svg?url'),
              heading:
                'Streamline secure remote access with easy-to-use CLI, API or UI',
              description:
                'Make it easy to access all applications and systems through a single workflow that works with existing tooling.',
            },
          ]}
        />
      </section>

      <section className="how-boundary-works">
        <HowBoundaryWorks
          heading="How Boundary works"
          description="HashiCorp Boundary is a secure access management solution that provides an easy way to allow access to applications and critical systems with fine-grained authorizations based on trusted identities. Across clouds, local data centers, low-trust networks, Boundary provides an easier way to protect and safeguard access to application and critical systems by trusted identities without exposing the underlying network"
          items={[
            'Platform-agnostic proxy for dynamic targets',
            'No SSH keys or VPN credentials to manage',
            'Just-in-time credentials via HashiCorp Vault',
          ]}
          img={{
            src: require('./img/how-boundary-works.png'),
            alt: 'How it works',
          }}
        />
      </section>

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

      <div className="use-cases-section">
        <div className="g-grid-container">
          <h2 className="g-type-display-2">Use cases</h2>
          <UseCases
            items={[
              {
                title: 'Identity-based access for dynamic environments',
                description:
                  'Configure identity-based access controls for your infrastructure, wherever it resides.',
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
                title: 'Compliance without overhead',
                description:
                  'Provide session visibility that enables teams to stay compliant.',
                image: {
                  url: require('./img/red-usecase-compliancewithoutoverhead.png?url'),
                },
                link: {
                  title: 'Learn more',
                  url:
                    'https://learn.hashicorp.com/tutorials/boundary/manage-users-groups',
                },
              },
              {
                title: 'Fully integrated secrets management',
                description:
                  'Just-in-time credentials from Vault for SSO to critical infrastructure targets.',
                image: {
                  url: require('./img/red-usecase-integratedsystem.png?url'),
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

      <BrandedCta
        heading="Ready to get started?"
        content="Boundary is an open source solution that automates a secure identity-based user access to hosts and services across environments."
        links={[
          {
            text: 'Download',
            url: '/download',
            type: 'download',
            icon: { position: 'right', isAnimated: true },
          },
          { text: 'Explore documentation', url: '/docs' },
        ]}
      />
    </div>
  )
}
