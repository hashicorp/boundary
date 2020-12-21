import VERSION from 'data/version.js'
import Head from 'next/head'
import HashiHead from '@hashicorp/react-head'
import { productName, productSlug } from 'data/metadata'
import ProductDownloader from '@hashicorp/react-product-downloader'
import styles from './style.module.css'

export default function DownloadsPage({ releases }) {
  return (
    <div className={styles.root}>
      <HashiHead is={Head} title={`Downloads | ${productName} by HashiCorp`} />
      <ProductDownloader
        releases={releases}
        packageManagers={[
          {
            label: 'Homebrew',
            commands: [
              'brew tap hashicorp/tap',
              'brew install hashicorp/tap/boundary',
            ],
            os: 'darwin',
          },
          {
            label: 'Ubuntu/Debian',
            commands: [
              'curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -',
              'sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"',
              'sudo apt-get update && sudo apt-get install boundary',
            ],
            os: 'linux',
          },
          {
            label: 'CentOS/RHEL',
            commands: [
              'sudo yum install -y yum-utils',
              'sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo',
              'sudo yum -y install boundary',
            ],
            os: 'linux',
          },
          {
            label: 'Fedora',
            commands: [
              'sudo dnf install -y dnf-plugins-core',
              'sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/fedora/hashicorp.repo',
              'sudo dnf -y install boundary',
            ],
            os: 'linux',
          },
          {
            label: 'Amazon Linux',
            commands: [
              'sudo yum install -y yum-utils',
              'sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo',
              'sudo yum -y install boundary',
            ],
            os: 'linux',
          },
        ]}
        productName={productName}
        productId={productSlug}
        latestVersion={VERSION}
        getStartedLinks={[
          {
            label: 'Install Boundary',
            href:
              'https://learn.hashicorp.com/tutorials/boundary/getting-started-install',
          },
          {
            label: 'Introduction to Boundary',
            href:
              'https://learn.hashicorp.com/tutorials/boundary/getting-started-intro',
          },
          {
            label: 'Start a Development Environment',
            href:
              'https://learn.hashicorp.com/tutorials/boundary/getting-started-dev',
          },
        ]}
        logo={
          <img
            className={styles.logo}
            alt="Boundary"
            src={require('./img/boundary-logo.svg')}
          />
        }
        brand="boundary"
        tutorialLink={{
          label: 'View Tutorial on HashiCorp Learn',
          href:
            'https://learn.hashicorp.com/tutorials/boundary/getting-started-install',
        }}
      />
    </div>
  )
}

export async function getStaticProps() {
  return fetch(`https://releases.hashicorp.com/boundary/index.json`, {
    headers: {
      'Cache-Control': 'no-cache',
    },
  })
    .then((res) => res.json())
    .then((result) => {
      return {
        props: {
          releases: result,
        },
      }
    })
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
