import s from './logo-list.module.css'

export default function LogoList({ logos }) {
  let formattedLogos = []
  if (logos) {
    if (logos.length > 6) {
      formattedLogos = logos.slice(0, 6)
      formattedLogos.push({
        url: '',
        alt: 'More integrations',
      })
    } else formattedLogos = logos
  }

  return (
    <div className={s.root}>
      {formattedLogos.length > 0
        ? logos.map((logo) => (
            <div key={logo.url} className={s.logo}>
              <img src={logo.url} alt={logo.company} />
            </div>
          ))
        : null}
    </div>
  )
}
