import { useState } from 'react'
import Collapsible from '../collapsible'
import SvgrChevronDown from '../chevron-down/black'
import styles from './property-object.module.css'

function PropertyObject({
  name,
  data,
  isFirstItem,
  isLastItem,
  arrayDepth = 0,
}) {
  const [isCollapsed, setIsCollapsed] = useState(true)
  const isArray = data.type === 'array'
  if (isArray)
    return (
      <PropertyObject
        name={name}
        data={data.items}
        arrayDepth={arrayDepth + 1}
        isFirstItem={isFirstItem}
        isLastItem={isLastItem}
      />
    )
  const hasProperties = data.type === 'object' && Boolean(data.properties)

  const typeArraySuffix =
    arrayDepth > 0 ? arrayFrom(arrayDepth, '[]').join('') : ''
  const typeString = `${data.type}${typeArraySuffix}`
  return (
    <div
      className={styles.root}
      data-is-first-item={isFirstItem}
      data-is-last-item={isLastItem}
    >
      <code className={`${styles.name} g-type-code`}>{name}</code>{' '}
      <code className={`${styles.typeString} g-type-code`}>{typeString}</code>{' '}
      {data.required ? (
        <span className={`${styles.requiredFlag} g-type-label-strong`}>
          Required
        </span>
      ) : null}
      {data.title && (
        <p className={`${styles.title} g-type-body-small`}>{data.title}</p>
      )}
      {data.description && (
        <p className={`${styles.description} g-type-body-small`}>
          {data.description}
        </p>
      )}
      {hasProperties && (
        <div>
          <button
            className={`${styles.toggleButton} g-type-body-small`}
            onClick={() => setIsCollapsed(!isCollapsed)}
          >
            <span className={styles.toggleIcon} data-is-collapsed={isCollapsed}>
              <SvgrChevronDown width={16} />
            </span>
            {isCollapsed ? 'Show properties' : 'Hide properties'}
          </button>
          <Collapsible isCollapsed={isCollapsed}>
            <div className={styles.propertiesContainer}>
              {Object.keys(data.properties).map((propertyKey, idx) => {
                return (
                  <PropertyObject
                    key={propertyKey}
                    name={propertyKey}
                    data={data.properties[propertyKey]}
                    isFirstItem={idx === 0}
                    isLastItem={idx === Object.keys(data.properties).length - 1}
                  />
                )
              })}
            </div>
          </Collapsible>
        </div>
      )}
    </div>
  )
}

function arrayFrom(length, value = null) {
  let array = []
  for (var i = 0; i < length; i++) {
    array.push(value)
  }
  return array
}

export default PropertyObject
