import './style.css'
import '@hashicorp/platform-util/nprogress/style.css'

import { useEffect } from 'react'
import * as Fathom from 'fathom-client'
import NProgress from '@hashicorp/platform-util/nprogress'
import createConsentManager from '@hashicorp/react-consent-manager/loader'
import useAnchorLinkAnalytics from '@hashicorp/platform-util/anchor-link-analytics'
import HashiStackMenu from '@hashicorp/react-hashi-stack-menu'
import Router, { useRouter } from 'next/router'
import HashiHead from '@hashicorp/react-head'
import { ErrorBoundary } from '@hashicorp/platform-runtime-error-monitoring'
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
  const router = useRouter()

  useEffect(() => {
    // Load Fathom analytics
    Fathom.load('AQKEGSAG', {
      includedDomains: ['boundaryproject.io', 'www.boundaryproject.io'],
    })

    function onRouteChangeComplete() {
      Fathom.trackPageview()
    }

    // Record a pageview when route changes
    router.events.on('routeChangeComplete', onRouteChangeComplete)

    // Unassign event listener
    return () => {
      router.events.off('routeChangeComplete', onRouteChangeComplete)
    }
  }, [])

  useAnchorLinkAnalytics()

  return (
    <ErrorBoundary FallbackComponent={Error}>
      <HashiHead
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
        <AlertBanner {...alertBannerData} product="boundary" hideOnMobile />
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
