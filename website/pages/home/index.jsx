import HomepageHero from 'components/homepage-hero'
import ProductFeaturesList from '@hashicorp/react-product-features-list'

const boundaryFeatures = [
  {
    title: 'Identity-based access',
    description:
      'Enables privileged sessions for users and  applications based on user identity and role.',
    icon: '',
  },
  {
    title: 'Identity-based access',
    description:
      'Enables privileged sessions for users and  applications based on user identity and role.',
    icon: '',
  },
  {
    title: 'Identity-based access',
    description:
      'Enables privileged sessions for users and  applications based on user identity and role.',
    icon: '',
  },
  {
    title: 'Identity-based access',
    description:
      'Enables privileged sessions for users and  applications based on user identity and role.',
    icon: '',
  },
  {
    title: 'Identity-based access',
    description:
      'Enables privileged sessions for users and  applications based on user identity and role.',
    icon: '',
  },
  {
    title: 'Identity-based access',
    description:
      'Enables privileged sessions for users and  applications based on user identity and role.',
    icon: '',
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
