import s from './logo-list.module.css'

export default function LogoList({ logos }) {
  return (
    <div className={s.root}>
      <div className={s.logos}>
        {logos.map((logo, stableIdx) => (
          <div
            // eslint-disable-next-line react/no-array-index-key
            key={stableIdx}
          >
            <img src={logo.url} width={logo.width} alt={logo.alt} />
          </div>
        ))}
      </div>
    </div>
  )
}
