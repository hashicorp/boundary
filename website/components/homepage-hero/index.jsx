import s from './style.module.css'
import Button from '@hashicorp/react-button'
import ReactPlayer from 'react-player'

export default function HomepageHero({ title, description, links, videoUrl }) {
  return (
    <div className={s.root}>
      <div className={s.contentContainer}>
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
        <div className={s.video}>
          <ReactPlayer
            url={videoUrl}
            width="596px"
            height="376px"
            style={{
              maxWidth: '100%',
            }}
          />
        </div>
      </div>
    </div>
  )
}
