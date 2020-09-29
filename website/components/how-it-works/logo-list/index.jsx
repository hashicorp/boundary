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
      {formattedLogos.map((logo) => (
        <div key={logo.url} className={s.logo}>
          <img src={logo.url} alt={logo.company} />
        </div>
      ))}
      <p className={`g-type-tag-label ${s.footerText}`}>
        Integrations coming soon
      </p>
    </div>
  )
}
