import s from './merch-desktop-client.module.css'
import InlineSvg from '@hashicorp/react-inline-svg'

export default function MerchDesktopDownload({ version, releases }) {
  const { builds } = releases.versions[version]

  return (
    <div className={s.container} id="desktop">
      <div className={s.wrapper}>
        <span className={s.title}>Desktop Client</span>
        <div className={s.platformVersion}>
          <InlineSvg
            className={s.logo}
            src={require('./img/apple-logo.svg?include')}
          />
          <span className={s.version}>{version}</span>
        </div>
        <div className={s.downloadLinks}>
          {builds.map((build) => (
            <a key={build.filename} className={s.downloadLink} href={build.url}>
              .{getFileExtension(build.filename)}
            </a>
          ))}
        </div>
      </div>
    </div>
  )
}

function getFileExtension(filename) {
  return filename.substring(filename.lastIndexOf('.') + 1, filename.length)
}
