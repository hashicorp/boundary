import HomepageHero from 'components/homepage-hero'
import ProductFeaturesList from '@hashicorp/react-product-features-list'

const boundaryFeatures = [
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
]

export default function HomePage() {
  return (
    <div className="p-home">
      <HomepageHero
        title="Identity-based secure access management"
        description="Access any system from anywhere based on user identity."
        links={[
          {
            text: 'Download',
            url: '/docs/getting-started/building',
            type: 'download',
          },
          {
            text: 'Get Started',
            url: '/docs/getting-started',
            type: 'inbound',
          },
        ]}
      />
      <ProductFeaturesList
        heading="Boundary Features"
        features={boundaryFeatures}
      />
    </div>
  )
}
