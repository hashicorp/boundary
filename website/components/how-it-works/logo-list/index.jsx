import s from './logo-list.module.css'

export default function LogoList({ logos }) {
  let formattedLogos = []
  if (logos.length > 6) {
    formattedLogos = logos.slice(0, 6)
    formattedLogos.push({
      url: '',
      alt: 'More integrations',
    })
  } else formattedLogos = logos

  return (
    <div className={s.root}>
      <div className={s.logos}>
        {formattedLogos.map((logo, stableIdx) => (
          <div
            // eslint-disable-next-line react/no-array-index-key
            key={stableIdx}
          >
            <img src={logo.url} alt={logo.alt} />
          </div>
        ))}
      </div>

      <p className={`g-type-tag-label ${s.footerText}`}>
        Integrations coming soon
      </p>
    </div>
  )
}
