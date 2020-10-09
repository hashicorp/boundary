import { useMemo, useState, useEffect } from 'react'
import VERSION from 'data/version.js'
import Head from 'next/head'
import HashiHead from '@hashicorp/react-head'

import { productName, productSlug } from 'data/metadata'
import {
  packageManagers,
  tutorials,
  containers,
  packageManagersByOs,
  getStartedLinks,
} from 'data/downloads'
import ReleaseInformation from 'components/downloader/release-information'
import { sortPlatforms, detectOs } from 'components/downloader/utils/downloader'
import DownloadCards from 'components/downloader/cards'
import styles from './style.module.css'

export default function DownloadsPage({ releaseData, previousVersions }) {
  const sortedDownloads = useMemo(() => sortPlatforms(releaseData), [
    releaseData,
  ])
  const osKeys = Object.keys(sortedDownloads)
  const [osIndex, setSelectedOsIndex] = useState()

  const tabData = Object.keys(sortedDownloads).map((osKey) => ({
    os: osKey,
    packageManagers: packageManagersByOs[osKey] || null,
  }))

  useEffect(() => {
    // if we're on the client side, detect the default platform only on initial render
    const index = osKeys.indexOf(detectOs(window.navigator.platform))
    setSelectedOsIndex(index)
  }, [])

  return (
    <div className={styles.root}>
      <h1>Download {productName}</h1>
      <HashiHead is={Head} title={`Downloads | ${productName} by HashiCorp`} />
      <DownloadCards
        brand="red"
        defaultTabIdx={osIndex}
        tabData={tabData}
        downloads={sortedDownloads}
        version={VERSION}
        logo={<div className={styles.logo}>{productName}</div>}
        tutorialLink={{
          label: 'View Tutorial on HashiCorp Learn',
          href:
            'https://learn.hashicorp.com/tutorials/boundary/getting-started-install',
        }}
      />

      <div className="g-container">
        <div className={styles.gettingStarted}>
          <h2>Getting Started</h2>
          <div className={styles.links}>
            {getStartedLinks.map((link) => (
              <a href={link.href} key={link.href}>
                {link.label}
              </a>
            ))}
          </div>
        </div>
      </div>

      <ReleaseInformation
        brand="red"
        productId={productSlug}
        productName={productName}
        releases={previousVersions}
        latestVersion={releaseData.version}
        packageManagers={Object.values(packageManagers)}
        containers={containers}
        tutorials={tutorials}
      />
    </div>
  )
}

export async function getStaticProps() {
  // NOTE: make sure to change "vault" here to your product slug
  return fetch(`https://releases.hashicorp.com/vault/${VERSION}/index.json`)
    .then((r) => r.json())
    .then((releaseData) => ({ props: { releaseData } }))
    .catch(() => {
      throw new Error(
        `--------------------------------------------------------
        Unable to resolve version ${VERSION} on releases.hashicorp.com from link
        <https://releases.hashicorp.com/${productSlug}/${VERSION}/index.json>. Usually this
        means that the specified version has not yet been released. The downloads page
        version can only be updated after the new version has been released, to ensure
        that it works for all users.
        ----------------------------------------------------------`
      )
    })
}
