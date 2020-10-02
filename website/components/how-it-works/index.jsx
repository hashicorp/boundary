import s from './how-it-works.module.css'
import HowBoundaryWorksDiagram from './how-boundary-works-diagram'
import Feature from './feature'
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
          {features.map((feature, index) => (
            <li key={feature.title}>
              <Feature
                {...feature}
                onInViewStatusChanged={(state) => {
                  if (state === true) setActiveExampleIndex(index)
                }}
              />
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
