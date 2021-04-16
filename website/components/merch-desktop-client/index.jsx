import s from './merch-desktop-client.module.css'
import InlineSvg from '@hashicorp/react-inline-svg'

export default function MerchDesktopDownload({ version, downloadLink }) {
  return (
    <div className={s.container}>
      <div className={s.wrapper}>
        <span className={s.title}>Desktop Client</span>
        <div className={s.platformVersion}>
          <InlineSvg src={require('./img/apple-logo.svg?include')} />
          <span className={s.version}>{version}</span>
        </div>
        <a className={s.downloadLink} href={downloadLink}>
          .dmg
        </a>
      </div>
    </div>
  )
}
