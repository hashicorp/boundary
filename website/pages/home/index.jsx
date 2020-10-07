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
        title="Identity-based secure access management"
        description="Access any system from anywhere based on user identity."
        links={[
          {
            text: 'Get Started',
            url:
              'https://learn.hashicorp.com/collections/boundary/getting-started',
            type: 'outbound',
          },
        ]}
        // TODO Replace URL with finalized URL
        videoUrl="https://www.youtube.com/watch?v=Y7c_twmDxQ4"
      />

      <HowItWorks
        title="Secure access to hosts and services"
        description="Traditional solutions require you to distribute and manage SSH keys, VPN credentials, and bastion hosts causing credential sprawl and opening user’s access to entire networks and systems. Boundary provides a secure way to access to hosts and critical systems without having to manage credentials or expose your network, and is entirely open source."
        features={[
          {
            title: 'Authenticate',
            description:
              'Authenticate with trusted identity provider access to hosts and services.',
            logos: [
              {
                alt: 'GitHub',
                url: require('./img/logos/github.svg?url'),
              },
              {
                alt: 'AWS',
                url: require('./img/logos/aws.svg?url'),
              },
              {
                alt: 'Microsoft Azure',
                url: require('./img/logos/azure.svg?url'),
              },
              {
                alt: 'Google Cloud Platform',
                url: require('./img/logos/gcp.svg?url'),
              },
              {
                alt: 'Okta',
                url: require('./img/logos/okta.svg?url'),
              },
              {
                alt: 'Ping',
                url: require('./img/logos/ping.svg?url'),
              },
              {
                alt: 'More integrations',
                url: require('./img/logos/more.svg?url'),
              },
            ],
          },
          {
            title: 'Authorize',
            description:
              'Authorize access to services and hosts based on roles and logical services.',
            logos: [
              {
                alt: 'Consul',
                url: require('./img/logos/consul.svg?url'),
              },
              {
                alt: 'AWS',
                url: require('./img/logos/aws.svg?url'),
              },
              {
                alt: 'Microsoft Azure',
                url: require('./img/logos/azure.svg?url'),
              },
              {
                alt: 'Terraform',
                url: require('./img/logos/terraform.svg?url'),
              },
              {
                alt: 'Google Cloud Platform',
                url: require('./img/logos/gcp.svg?url'),
              },
              {
                alt: 'Kubernetes',
                url: require('./img/logos/kubernetes.svg?url'),
              },
              {
                url: require('./img/logos/more.svg?url'),
                alt: 'More integrations',
              },
            ],
          },
          {
            title: 'Access',
            description:
              'Securely connect with just-in-time access without exposing or distributing credentials.',
          },
        ]}
      />

      <div className="use-cases-section">
        <div className="g-grid-container">
          <h2 className="g-type-display-2">Use cases</h2>
          <UseCases
            items={[
              {
                title: 'Onboard new users effortlessly',
                description:
                  'Enables and secures access across dynamic environments.',
                image: {
                  url: require('./img/red-usecase-accessmgmt.png?url'),
                },
                link: { title: 'Learn more', url: '#TODO' },
              },
              {
                title: 'Connect to private resources easily',
                description:
                  'Securely connect trusted identities to applications, systems, and data.',
                image: {
                  url: require('./img/red-usecase-accessprivileges.png?url'),
                },
                link: {
                  title: 'Learn more',
                  url: '/docs/common-workflows/manage-identities',
                },
              },
              {
                title: 'Security and compliance without overhead',
                description:
                  'Provides session visibility that enables teams to stay compliant.',
                image: {
                  url: require('./img/red-usecase-sessionvisibility.png?url'),
                },
                link: {
                  title: 'Learn more',
                  url: '/docs/common-workflows/manage-sessions',
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
            },
            {
              title: 'Session management',
              content:
                'Ensures access control regardless of user or operators’ infrastructure.',
              icon: require('./img/features/session-management.svg?url'),
            },
            {
              title: 'Platform agnostic',
              content:
                'One workflow for identity-based access across clouds, kubernetes clusters, and on-prem infrastructure.',
              icon: require('./img/features/platform-agnosticity.svg?url'),
            },
            {
              title: 'Session visibility',
              content:
                'Visibility into session metrics, events, logs, and traces with the ability to export data to business intelligence and event monitoring tools.',
              icon: require('./img/features/session-visibility.svg?url'),
            },
            {
              title: 'Configuration as code',
              content:
                'Ability to establish secure access controls and route resources dynamically.',
              icon: require('./img/features/config-as-code.svg?url'),
            },
            {
              title: 'Managing dynamic environments',
              content:
                'Secure access to dynamic systems and applications with automated controls.',
              icon: require('./img/features/managing-dynamic-environments.svg?url'),
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
