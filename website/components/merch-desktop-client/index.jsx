import s from './merch-desktop-client.module.css'
import InlineSvg from '@hashicorp/react-inline-svg'

export default function MerchDesktopDownload({ version, releases }) {
  const { builds } = releases.versions[version]

  // Calculate all Operating Systems that we have versions for
  // and place their respective builds under them
  const operatingSystems = builds
    .map((build) => {
      return build.os
    })
    .filter((value, index, self) => {
      // Parse out duplicates
      return self.indexOf(value) === index
    })
    .map((os) => {
      // Add the respective builds under their OS
      return {
        os: os,
        builds: builds.filter((build) => {
          return build.os === os
        }),
      }
    })

  return (
    <div className={s.container} id="desktop">
      <div className={s.wrapper}>
        <span className={s.title}>Desktop Client - {version}</span>
        <ul className={s.downloadsList}>
          {operatingSystems.map((operatingSystem) => {
            return (
              <li key={operatingSystem.os}>
                <InlineSvg
                  src={require(`./img/${operatingSystem.os}.svg?include`)}
                />
                <ul className={s.versionsList}>
                  {operatingSystem.builds.map((build) => {
                    return (
                      <li key={build.filename} className={s.versionDownload}>
                        <a href={build.url}>
                          .{getFileExtension(build.filename)} (
                          {humanArch(build.arch)})
                        </a>
                      </li>
                    )
                  })}
                </ul>
              </li>
            )
          })}
        </ul>
      </div>
    </div>
  )
}

function humanArch(arch) {
  if (arch === '386') {
    return '32-bit'
  }
  if (arch === 'amd64') {
    return '64-bit'
  }
  return arch
}

function getFileExtension(filename) {
  return filename.substring(filename.lastIndexOf('.') + 1, filename.length)
}
