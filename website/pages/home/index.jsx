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
            text: 'Download',
            url: '/download',
            type: 'download',
          },
          {
            text: 'Documentation',
            url: '/docs',
            type: 'inbound',
          },
        ]}
        // TODO Replace URL with finalized URL
        videoUrl="https://www.youtube.com/watch?v=Y7c_twmDxQ4"
      />

      <HowItWorks
        sections={[
          {
            title: 'Authenticate',
            description:
              'Authenticate with trusted identity provider access to hosts and services.',
            logos: [],
            footerText: 'Integrations coming soon',
          },
          {
            title: 'Authorize',
            description:
              'Authorize access to services and hosts based on roles and logical services.',
            logos: [],
            footerText: 'Integrations coming soon',
          },
          {
            title: 'Access',
            description:
              'Securely connect with just-in-time access without exposing or distributing credentials.',
            footerText: 'Integrations coming soon',
          },
        ]}
      />

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

      <ProductFeaturesList
        heading="Boundary Features"
        features={[
          {
            title: 'Identity-based access',
            content:
              'Enables privileged sessions for users and  applications based on user identity and role.',
            icon: require('./img/boundary-identitybasedaccess.jpg?url'),
          },
          {
            title: 'Session management',
            content:
              'Ensures access control regardless of user or operators’ infrastructure.',
            icon: require('./img/boundary-sessionmanagement.jpg?url'),
          },
          {
            title: 'Platform agnostic',
            content:
              'One workflow for identity-based access across clouds, kubernetes clusters, and on-prem infrastructure.',
            icon: require('./img/boundary-platformagnosticity.jpg?url'),
          },
          {
            title: 'Session visibility',
            content:
              'Visibility into session metrics, events, logs, and traces with the ability to export data to business intelligence and event monitoring tools.',
            icon: require('./img/boundary-sessionvisibility.jpg?url'),
          },
          {
            title: 'Configuration as code',
            content:
              'Ability to establish secure access controls and route resources dynamically.',
            icon: require('./img/boundary-configascode.jpg?url'),
          },
          {
            title: 'Managing dynamic environments',
            content:
              'Secure access to dynamic systems and applications with automated controls.',
            icon: require('./img/boundary-managingdynamicenvironments.jpg?url'),
          },
        ]}
      />

      <div className="use-cases-section">
        <div className="g-grid-container">
          <h2 className="g-type-display-2">Use cases</h2>
          <UseCases
            items={[
              {
                title: 'Identity-based access',
                description:
                  'Securely connect trusted identities to applications, systems, and data.',
                image: {
                  url: require('./img/red-usecase-accessprivileges.png?url'),
                },
                link: { title: 'Learn more', url: '#TODO' },
              },
              {
                title: 'Automate access',
                description:
                  'Enables secure access across dynamic infrastructure.',
                image: {
                  url: require('./img/red-usecase-accessmgmt.png?url'),
                },
                link: { title: 'Learn more', url: '#TODO' },
              },
              {
                title: 'Session visibility',
                description:
                  'Monitor user sessions created with Boundary with your preferred analytics tool.',
                image: {
                  url: require('./img/red-usecase-sessionvisibility.png?url'),
                },
                link: { title: 'Learn more', url: '#TODO' },
              },
            ]}
          />
        </div>
      </div>

      <BrandedCta
        heading="Ready to get started?"
        content="Boundary is an open source solution that automates a secure identity-based user access to hosts and services across environments."
        links={[
          { text: 'Download', url: '/download', type: 'download' },
          { text: 'Explore documentation', url: '/docs' },
        ]}
      />
    </div>
  )
}
