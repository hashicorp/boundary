import s from './style.module.css'

export default function HowBoundaryWorks({ heading, description, items, img }) {
  return (
    <div className={s.root}>
      <div className={s.inner}>
        <div className="content">
          <h2 className={s.heading}>{heading}</h2>
          <p className={s.description}>{description}</p>
          <ul className={s.items}>
            {items.map((item, index) => {
              // Index is stable
              // eslint-disable-next-line react/no-array-index-key
              return (
                <li key={index} className={s.item}>
                  {item}
                </li>
              )
            })}
          </ul>
        </div>
        <div className={s.media}>
          <img src={img.src} alt={img.alt} />
        </div>
      </div>
    </div>
  )
}
