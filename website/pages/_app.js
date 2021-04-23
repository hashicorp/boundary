import './style.css'
import '@hashicorp/nextjs-scripts/lib/nprogress/style.css'
import NProgress from '@hashicorp/nextjs-scripts/lib/nprogress'
import createConsentManager from '@hashicorp/nextjs-scripts/lib/consent-manager'
import useAnchorLinkAnalytics from '@hashicorp/nextjs-scripts/lib/anchor-link-analytics'
import HashiStackMenu from '@hashicorp/react-hashi-stack-menu'
import Router from 'next/router'
import HashiHead from '@hashicorp/react-head'
import Head from 'next/head'
import { ErrorBoundary } from '@hashicorp/nextjs-scripts/lib/bugsnag'
import ProductSubnav from '../components/subnav'
import Footer from 'components/footer'
import Error from './_error'
import AlertBanner from '@hashicorp/react-alert-banner'
import alertBannerData, { ALERT_BANNER_ACTIVE } from 'data/alert-banner'

NProgress({ Router })
const { ConsentManager, openConsentManager } = createConsentManager({
  preset: 'oss',
})

const title = 'Boundary by HashiCorp'
const description =
  'Boundary is an open source solution that automates a secure identity-based user access to hosts and services across environments.'

export default function App({ Component, pageProps }) {
  useAnchorLinkAnalytics()

  return (
    <ErrorBoundary FallbackComponent={Error}>
      <HashiHead
        is={Head}
        title={title}
        siteName={title}
        description={description}
        image="https://www.boundaryproject.io/img/og-image.png"
        icon={[{ href: '/_favicon.ico' }]}
      >
        <meta name="og:title" property="og:title" content={title} />
        <meta name="og:description" property="og:title" content={description} />
      </HashiHead>
      {ALERT_BANNER_ACTIVE && (
        <AlertBanner {...alertBannerData} product="boundary" />
      )}
      <HashiStackMenu />
      <ProductSubnav />
      <div className="content">
        <Component {...pageProps} />
      </div>
      <Footer openConsentManager={openConsentManager} />
      <ConsentManager />
    </ErrorBoundary>
  )
}
