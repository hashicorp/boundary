import Subnav from '@hashicorp/react-subnav'
import { useRouter } from 'next/router'
import subnavItems from 'data/navigation'
import { productSlug } from 'data/metadata'
import Link from 'next/link'

export default function ProductSubnav() {
  const router = useRouter()
  return (
    <Subnav
      titleLink={{
        text: 'Boundary',
        url: '/',
      }}
      ctaLinks={[
        {
          text: 'GitHub',
          url: `https://www.github.com/hashicorp/${productSlug}`,
        },
        {
          text: 'Download',
          url: '/downloads',
        },
      ]}
      currentPath={router.asPath}
      menuItemsAlign="right"
      menuItems={subnavItems}
      constrainWidth
      Link={Link}
      matchOnBasePath
    />
  )
}
