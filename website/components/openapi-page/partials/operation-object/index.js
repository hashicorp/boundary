import React from 'react'
import Collapsible from '../collapsible'
import ResponseObject from '../response-object'
import PropertyObject from '../property-object'
import { capitalCase } from 'change-case'
import useHover from '../../../../lib/hooks/use-hover'
import SvgrChevronDown from '../chevron-down/black'

import styles from './operation-object.module.css'

function OperationObject({
  data,
  path,
  type,
  isHighlighted,
  isCollapsed,
  setIsCollapsed,
}) {
  const [headerRef, isHeaderHovered] = useHover()

  // const [isCollapsed, setIsCollapsed] = useState(true)
  const { operationId, parameters, responses, summary } = data
  const successResponse = responses['200']
  const title = capitalCase(operationId.split('_').slice(1).join())

  // Group parameter properties by type
  const pathParams = parameters.filter((p) => p.in === 'path')
  const queryParams = parameters.filter((p) => p.in === 'query')
  const bodyParam = parameters.filter((p) => p.in === 'body')[0] // Note: we only accept a single "in=body" param
  const bodyProps = bodyParam ? getBodyParamProps(bodyParam) : []

  return (
    <div className={styles.root} data-is-hovered={isHeaderHovered}>
      <div
        className={styles.header}
        ref={headerRef}
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <div className={styles.meta}>
          <div
            className={styles.title}
            data-is-highlighted={isHighlighted}
            data-is-hovered={isHeaderHovered}
          >
            {title}
          </div>
          <div className={styles.endpoint}>
            <span className={styles.method} data-is-hovered={isHeaderHovered}>
              {type.toUpperCase()}{' '}
            </span>
            <span className={styles.path}>{path}</span>
          </div>
        </div>
        <div className={styles.toggleButton}>
          <span className={styles.toggleText}>
            {isCollapsed ? 'Expand' : 'Collapse'}
          </span>
          <span className={styles.toggleIcon} data-is-collapsed={isCollapsed}>
            <SvgrChevronDown width={16} />
          </span>
        </div>
      </div>
      <Collapsible isCollapsed={isCollapsed}>
        <div className={styles.details}>
          <p className={styles.summary}>{summary}</p>
          <TwoColumnLayout
            columnOne={
              <div>
                <ColumnHeading title="Request" />
                {pathParams.length > 0 ? (
                  <Parameters title="Path Parameters" params={pathParams} />
                ) : null}
                {queryParams.length > 0 ? (
                  <Parameters title="Query Parameters" params={queryParams} />
                ) : null}
                {bodyProps.length > 0 ? (
                  <Parameters title="Body Parameters" params={bodyProps} />
                ) : null}
              </div>
            }
            columnTwo={
              <div>
                <ColumnHeading title="Response" />
                {!!successResponse ? (
                  <div>
                    <ColumnSectionHeading title="Successful Response" />
                    <ResponseObject data={successResponse} />
                  </div>
                ) : (
                  <p>No response has been defined.</p>
                )}
              </div>
            }
          />
        </div>
      </Collapsible>
    </div>
  )
}

function getBodyParamProps(bodyParam) {
  // We always expect the bodyParam to be an object,
  // with a schema which defines the body properties.
  if (!bodyParam.schema || !bodyParam.schema.properties) return []
  // We flatten these properties to avoid showing a
  // "collapsed object" UI under the "Body Parameters" section,
  // which would be a bit redundant and annoying to have to expand
  const bodyPropsObj = bodyParam.schema.properties
  const bodyProps = Object.keys(bodyPropsObj).reduce((acc, key) => {
    const data = Object.assign({}, bodyPropsObj[key])
    //  We need the property name. This is usually be handled by "key" in an object,
    // but we're flattening the object so we need to make sure it's there
    data.name = key
    if (!data.readOnly) acc.push(data)
    return acc
  }, [])
  return bodyProps
}

function ColumnHeading({ title }) {
  return (
    <p
      style={{
        margin: '0 0 1em 0',
        fontWeight: 'bold',
      }}
    >
      {title}
    </p>
  )
}

function ColumnSectionHeading({ title }) {
  return (
    <p
      style={{
        margin: 0,
        paddingBottom: '8px',
        borderBottom: '1px solid var(--gray-6)',
        color: 'var(--gray-4)',
      }}
      className="g-type-label-strong"
    >
      {title}
    </p>
  )
}

function TwoColumnLayout({ columnOne, columnTwo }) {
  return (
    <div style={{ display: 'flex' }}>
      <div
        style={{
          width: 'calc(50% - 16px)',
          position: 'relative',
        }}
      >
        {columnOne}
      </div>
      <div
        style={{
          width: '32px',
        }}
      ></div>
      <div
        style={{
          width: 'calc(50% - 16px)',
          position: 'relative',
        }}
      >
        {columnTwo}
      </div>
    </div>
  )
}

function Parameters({ title, params }) {
  return (
    <div>
      <ColumnSectionHeading title={title} />
      {params.map((parameter, idx) => {
        return (
          <PropertyObject
            key={parameter.name}
            name={parameter.name}
            data={parameter}
            isFirstItem={idx === 0}
            isLastItem={idx === params.length - 1}
          />
        )
      })}
    </div>
  )
}

export default OperationObject
