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
        title="Identity-based access for zero trust security"
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
                alt: 'More integrations',
                url: require('./img/logos/custom.svg?url'),
              },
            ],
          },
          {
            title: 'Access',
            description: (
              <>
                Reduce risk of leaking credentials with dynamic secrets and
                just-in-time credentials. Automate credential injection to
                securely access services and hosts with{' '}
                <a href="https://learn.hashicorp.com/tutorials/boundary/vault-cred-brokering-quickstart">
                  HashiCorp Vault
                </a>
                .
              </>
            ),
            logos: [
              {
                alt: 'Postgresql',
                url: require('./img/logos/postgresql.png?url'),
                width: 36,
              },
              {
                alt: 'SSH',
                url: require('./img/logos/ssh.svg?url'),
                width: 42,
              },
              {
                alt: 'Mongo DB',
                url: require('./img/logos/mongo-db.svg?url'),
              },
              {
                alt: 'AWS',
                url: require('./img/logos/aws-color.svg?url'),
              },
              {
                alt: 'Unknown',
                url: require('./img/logos/unknown.svg?url'),
              },
              {
                alt: 'MySQL',
                url: require('./img/logos/my-sql-color.svg?url'),
              },
              {
                alt: 'More integrations',
                url: require('./img/logos/custom.svg?url'),
              },
            ],
          },
        ]}
      />

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
                'Streamline remote access with easy-to-use CLI, API or UI',
              description:
                'Make it easy to access all applications and systems through a single workflow that works with existing tooling.',
            },
          ]}
        />
      </section>

      <section className="how-boundary-works">
        <HowBoundaryWorks
          heading="How Boundary Works"
          description="HashiCorp Boundary is a secure remote access solution that provides an easy way to allow access to applications and critical systems with fine-grained authorizations based on trusted identities. Across clouds, local data centers, low-trust networks, Boundary provides an easier way to protect and safeguard access to application and critical systems by trusted identities without exposing the underlying network"
          items={[
            'Platform-agnostic proxy for dynamic targets',
            'No SSH keys or VPN credentials to manage',
            'Just-in-time credentials via HashiCorp Vault',
          ]}
          img={{
            src: require('./img/how-boundary-works.svg'),
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
              icon: require('./img/icons/user.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/getting-started-intro',
              },
            },
            {
              title: 'Session visibility and audit logs',
              content:
                'Visibility into session metrics, events, logs, and traces with the ability to export data to business intelligence and event monitoring tools.',
              icon: require('./img/icons/activity.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/manage-sessions?in=boundary/common-workflows',
              },
            },
            {
              title: 'Seamless IDP integration',
              content:
                'Integrate with IDP of choice, including Azure Active Directory, Okta, and many others that support Open ID Connect.',
              icon: require('./img/icons/star.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url: 'https://learn.hashicorp.com/tutorials/boundary/oidc-auth',
              },
            },
            {
              title: 'Dynamic secrets management',
              content:
                'Leverage Vault integration for the brokering of Vault secrets to Boundary clients via the command line and desktop clients for use in Boundary sessions.',
              icon: require('./img/icons/lock.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/vault-cred-brokering-quickstart',
              },
            },
            {
              title: 'Dynamic service discovery',
              content:
                'Automate service discovery and access configuration as workloads are deployed or changed. Coming soon.',
              icon: require('./img/icons/layers.svg?url'),
            },
            {
              title: 'Infrastructure as code',
              content:
                'Define policies and manage Boundary with an Infrastructure as Code approach. Terraform provider supports the full breadth of Boundary configurations.',
              icon: require('./img/icons/terminal.svg?url'),
              link: {
                type: 'inbound',
                text: 'Learn more',
                url:
                  'https://learn.hashicorp.com/tutorials/boundary/getting-started-config',
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
                  url: 'https://learn.hashicorp.com/boundary',
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
                    'https://learn.hashicorp.com/tutorials/boundary/manage-sessions',
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
                    'https://learn.hashicorp.com/tutorials/boundary/vault-cred-brokering-quickstart',
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
