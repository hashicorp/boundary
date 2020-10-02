import s from './how-it-works.module.css'
import LogoList from './logo-list'
import HowBoundaryWorksDiagram from './how-boundary-works-diagram'
import { useState } from 'react'

export default function HowItWorks({ features }) {
  const [activeExampleIndex, setActiveExampleIndex] = useState(0)

  return (
    <div className={s.root}>
      <h2 className="g-type-display-2">How it works</h2>
      <div className={`g-grid-container ${s.contentContainer}`}>
        <div className={s.diagram}>
          <HowBoundaryWorksDiagram activeExampleIndex={activeExampleIndex} />
        </div>
        <ul className={s.features}>
          {features.map(({ title, description, logos }) => (
            <li
              key={title}
              // TODO Move to an InView threshold check; this is for testing
              onClick={() => {
                setActiveExampleIndex(activeExampleIndex + 1)
              }}
            >
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
