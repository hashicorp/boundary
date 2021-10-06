import LogoList from './logo-list'
import s from './feature.module.css'
import { useInView } from 'react-intersection-observer'
import { useState } from 'react'

export default function Feature({
  title,
  description,
  logos,
  onInViewStatusChanged,
}) {
  const [ref, inView] = useInView({ threshold: 0.8 })
  const [inViewStatus, setInViewStatus] = useState(false)
  if (inView != inViewStatus) {
    setInViewStatus(inView)
    onInViewStatusChanged(inView)
  }

  return (
    <div className={s.root} ref={ref}>
      <h3 className="g-type-display-4">{title}</h3>
      <p className="g-type-body">{description}</p>
      {logos ? <LogoList logos={logos} /> : null}
    </div>
  )
}
