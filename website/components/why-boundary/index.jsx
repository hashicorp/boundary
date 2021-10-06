import s from './style.module.css'

export default function WhyBoundary({ heading, items }) {
  return (
    <div className={s.root}>
      <h2 className={s.heading}>{heading}</h2>
      <ul className={s.items}>
        {items.map((item, index) => {
          return (
            // Index is stable
            // eslint-disable-next-line react/no-array-index-key
            <li key={index}>
              <img className={s.itemIcon} src={item.icon} alt={item.heading} />
              <h3 className={s.itemHeading}>{item.heading}</h3>
              <p className={s.itemDescription}>{item.description}</p>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
