import HomepageHero from 'components/homepage-hero'

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
    </div>
  )
}
