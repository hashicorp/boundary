import s from './how-it-works.module.css'
import HowBoundaryWorksDiagram from './how-boundary-works-diagram'
import Feature from './feature'
import { useState } from 'react'

export default function HowItWorks({ title, description, features }) {
  const [activeExampleIndex, setActiveExampleIndex] = useState(0)
  const [viewportStatus, setViewportStatus] = useState(
    new Array(features.length).fill(false)
  )

  return (
    <div className={s.root}>
      <div className={s.intro}>
        <h2 className={s.introTitle}>{title}</h2>
        <div className={s.introDescription}>{description}</div>
      </div>
      <div className={s.contentContainer}>
        <div className={s.diagram}>
          <HowBoundaryWorksDiagram activeExampleIndex={activeExampleIndex} />
        </div>
        <ul className={s.features}>
          {features.map((feature, index) => (
            <li key={feature.title}>
              <Feature
                {...feature}
                onInViewStatusChanged={(state) => {
                  const newStatusArray = [...viewportStatus]
                  newStatusArray[index] = state
                  setViewportStatus(newStatusArray)
                  // Calculate the first element in focus, set that as
                  // our new activeExampleIndex. If it's been updated
                  // notify the subscriber.
                  const newExampleIndex = newStatusArray.lastIndexOf(true)
                  if (
                    activeExampleIndex != newExampleIndex &&
                    newExampleIndex != -1
                  ) {
                    setActiveExampleIndex(newExampleIndex)
                  }
                }}
              />
            </li>
          ))}
        </ul>
      </div>
    </div>
  )
}
