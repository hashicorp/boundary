import s from './style.module.css'
import Button from '@hashicorp/react-button'

export default function HomepageHero({ title, description, links }) {
  return (
    <div className={s.root}>
      <div className="g-grid-container">
        <div className={s.contentAndLinks}>
          <h1 className="g-type-display-1">{title}</h1>
          <p className="g-type-body-large">{description}</p>
          <div className={s.links}>
            {links.map((link, index) => {
              const brand = index === 0 ? 'hashicorp' : 'neutral'
              const variant = index === 0 ? 'primary' : 'secondary'
              return (
                <Button
                  key={link.text}
                  title={link.text}
                  linkType={link.type}
                  url={link.url}
                  theme={{ variant, brand }}
                />
              )
            })}
          </div>
        </div>
        <div className={s.image}></div>
      </div>
    </div>
  )
}
