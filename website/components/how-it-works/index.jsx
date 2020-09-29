import s from './how-it-works.module.css'
import LogoList from './logo-list'

export default function HowItWorks({ features }) {
  return (
    <div className={s.root}>
      <h2 className="g-type-display-2">How it works</h2>
      <div className={`g-grid-container ${s.contentContainer}`}>
        <div className={s.image}>
          <img alt="" src={require('./img/how-it-works.jpg?url')} />
        </div>
        <ul className={s.features}>
          {features.map(({ title, description, logos }) => (
            <li key="title">
              <h4 className="g-type-display-4">{title}</h4>
              <p className="g-type-body">{description}</p>
              {logos ? <LogoList logos={logos} /> : null}
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
