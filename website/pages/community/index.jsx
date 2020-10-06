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
        description="Boundary is a newly-launched open source project.  The project team depends on the community’s engagement and feedback.  Get involved today."
        use_h1={true}
      />
      <VerticalTextBlockList
        data={[
          {
            header: 'Community Forum',
            body:
              '[Boundary Community Forum](https://discuss.hashicorp.com/c/boundary)',
          },
          {
            header: 'Bug Tracker',
            body:
              '[Issue tracker on GitHub](https://github.com/hashicorp/boundary/issues). Please only use this for reporting bugs. Do not ask for general help here; use the Community Form for that.',
          },
        ]}
      />
    </div>
  )
}
