import VerticalTextBlockList from '@hashicorp/react-vertical-text-block-list'
import SectionHeader from '@hashicorp/react-section-header'
import Head from 'next/head'

export default function CommunityPage() {
  return (
    <div id="p-community">
      <Head>
        <title key="title">Community | Boundary by HashiCorp</title>
      </Head>
      <SectionHeader
        headline="Community"
        description="Boundary is a newly-launched open source project. The project team depends on the community’s engagement and feedback. Get involved today."
        use_h1={true}
      />
      <VerticalTextBlockList
        product="boundary"
        data={[
          {
            header: 'Community Forum',
            body:
              '<a href="https://discuss.hashicorp.com/c/boundary">Boundary Community Forum</a>',
          },
          {
            header: 'Bug Tracker',
            body:
              '<a href="https://github.com/hashicorp/boundary/issues">Issue tracker on GitHub</a>. Please only use this for reporting bugs. Do not ask for general help here; use the Community Form for that.',
          },
        ]}
      />
    </div>
  )
}
