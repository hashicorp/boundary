import s from './how-it-works.module.css'

export default function HowItWorks({ sections }) {
  return (
    <div className={s.root}>
      <h2 className="g-type-display-2">How it works</h2>
      <div className={`g-grid-container ${s.contentContainer}`}>
        <div className={s.image}>
          <img alt="" src={require('./img/how-it-works.jpg?url')} />
        </div>
        <ul className={s.sections}>
          {/* TODO Remove sections ternary when sections is no longer temp */}
          {sections
            ? sections.map(({ title, description, logos, footerText }) => (
                <li key="title">
                  <h4 className="g-type-display-4">{title}</h4>
                  <p className="g-type-body">{description}</p>
                  {logos ? (
                    <div>{`<LogoList logos={logos} /> here`}</div>
                  ) : null}
                  {footerText ? (
                    <p className={`g-type-tag-label ${s.footerText}`}>
                      {footerText}
                    </p>
                  ) : null}
                </li>
              ))
            : null}
        </ul>
      </div>
    </div>
  )
}
