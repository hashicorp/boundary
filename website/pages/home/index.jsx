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
            url: '#',
            type: 'download',
          },
          {
            text: 'Get Started',
            url: '/docs/introduction',
            type: 'inbound',
          },
        ]}
      />
    </div>
  )
}
