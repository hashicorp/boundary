import { useState, useRef } from 'react'
import { useRouter } from 'next/router'
import Head from 'next/head'
import Link from 'next/link'
import OperationObject from './partials/operation-object'
import DocsPage from '@hashicorp/react-docs-page'
import { getPathsFromSchema, getPropsForPage } from './utils/routing-utils'
import styles from './openapi-page.module.css'
import useOnClickOutside from 'lib/hooks/use-on-click-outside'

function OpenApiPage({
  info,
  operationCategory,
  sidenavOrder,
  productName,
  productSlug,
  pathFromRoot,
}) {
  const router = useRouter()
  const operationsRef = useRef(null)
  const [expandedOperations, setExpandedOperations] = useState([])
  useOnClickOutside(operationsRef, () => setExpandedOperations([]))

  function setOperationState(slug, isExpanded) {
    const newStates = expandedOperations.filter((s) => s !== slug)
    if (isExpanded) newStates.push(slug)
    setExpandedOperations(newStates)
  }

  const pageTitle = operationCategory ? operationCategory.name : info.title

  return (
    <div className={styles.root} data-theme={productSlug}>
      <DocsPage
        head={{
          is: Head,
          title: `${pageTitle} | ${productName} by HashiCorp`,
          description: info.description,
          siteName: `${productName} by HashiCorp`,
        }}
        product="vault"
        resourceURL={`https://github.com/hashicorp/${productSlug}`}
        sidenav={{
          Link,
          currentPage: router.asPath,
          category: pathFromRoot,
          disableFilter: true,
          order: sidenavOrder,
          data: [],
        }}
      >
        {operationCategory ? (
          <div>
            <p className={`${styles.pageHeading} g-type-display-2`}>
              {info.title}
            </p>
            <h1 className={`${styles.categoryHeading} g-type-display-4`}>
              {operationCategory.name}
            </h1>
            <div ref={operationsRef}>
              {operationCategory.operations.map((op) => {
                const isExpanded =
                  expandedOperations.indexOf(op.operationId) !== -1

                return (
                  <OperationObject
                    key={op.__type + op.__path}
                    path={op.__path}
                    type={op.__type}
                    data={op}
                    isCollapsed={!isExpanded}
                    setIsCollapsed={(isCollapsed) =>
                      setOperationState(op.operationId, !isCollapsed)
                    }
                  />
                )
              })}
            </div>
          </div>
        ) : (
          <div>
            <h1 className={`${styles.pageHeading} g-type-display-2`}>
              {info.title}
            </h1>
            <p className={`${styles.landingPlaceholder} g-type-body-long`}>
              Select a service from the sidebar.
            </p>
          </div>
        )}
      </DocsPage>
    </div>
  )
}

export { getPathsFromSchema, getPropsForPage }
export default OpenApiPage
