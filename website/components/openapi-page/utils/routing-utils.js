import { capitalCase } from 'change-case'
import slugify from '@hashicorp/remark-plugins/generate_slug'

/* Gieven a schema, current service slug, and parentPath, return all props needed for an openapi component page */
export function getPropsForPage(schema, params) {
  // parse the data we'll show to the user from the schema
  const operationObjects = getOperationObjects(schema)
  const serviceIds = getServiceIds(operationObjects)
  // info and sidenav data are needed on all pages
  const info = schema.info
  const navData = getSidenavData(serviceIds)
  // If there's no "page" param, then this is the landing page
  const isLanding = !params || !params.page || params.page.length == 0

  const currentPath = params && params.page ? params.page.join('/') : ''

  // Otherwise, we should have an operationCategory that matches the slug-ified ID from the URL path
  const operationCategory = isLanding
    ? false
    : serviceIds
        .filter((id) => getServiceSlug(id) === params.page[0])
        .map((serviceId) => {
          const name = capitalCase(serviceId)
          const slug = getServiceSlug(serviceId)
          const operations = operationObjects.filter(
            (o) => getServiceId(o.operationId) === serviceId
          )
          return { name, slug, operations }
        })[0]

  return { info, navData, operationCategory, currentPath }
}

/* Given a schema, return all the paths we'll render for our openapi generated docs */
export function getPathsFromSchema(schema) {
  // Assign each operation category to a URL using its slug-ified ID
  const operationObjects = getOperationObjects(schema)
  const slugs = getServiceIds(operationObjects).map(getServiceSlug)
  // We need a path for each "service"
  const paths = slugs.map((slug) => ({ params: { page: [slug] } }))
  // We also push a path for an "/" index page
  paths.push({ params: { page: [] } })
  return paths
}

/* Given a list of service ids, return an object suitable to pass to <DocsSidenav />
to render a flat list of services */
function getSidenavData(serviceIds) {
  const order = serviceIds.map((serviceId) => {
    return {
      title: capitalCase(serviceId),
      indexData: true,
      path: getServiceSlug(serviceId),
    }
  })
  return order
}

/* Given a serviceId, which is typically PascalCase string, return a slugified kebab-case string (ie: pascal-case rather than pascalcase) */
function getServiceSlug(serviceId) {
  return slugify(capitalCase(serviceId))
}

/* Given an operationId, return the "serviceId" */
function getServiceId(operationId) {
  // We expect operationIds to have two parts, separated by an underscore
  // The "serviceId" is the first part of the value
  return operationId.split('_')[0]
}

/* Given a schema, return an array of unique operation "category" strings */
export function getServiceIds(operationObjects) {
  const operationIdCategories = operationObjects
    .map((o) => getServiceId(o.operationId))
    .sort()
  // Several related operationIds may have the same "category" part,
  // so we filter for unique values before returning
  return filterUnique(operationIdCategories)
}

/* Given an array of values, return an array without duplicate items */
function filterUnique(array) {
  return array.filter((value, idx) => array.indexOf(value) === idx)
}

/* Given a schema, return a flattened list of operation objects */
function getOperationObjects(schema) {
  const pathItemObjects = Object.keys(schema.paths).reduce((acc, path) => {
    acc.push({ __path: path, ...schema.paths[path] })
    return acc
  }, [])

  const operationObjects = pathItemObjects.reduce((acc, pathItemObject) => {
    // Each path can support many operations through different request types
    const requestTypes = [
      'get',
      'put',
      'post',
      'delete',
      'options',
      'head',
      'patch',
    ]
    const pathOperations = requestTypes.reduce((acc, type) => {
      //  Not all paths will support every request type
      if (!pathItemObject[type]) return acc
      // If the request type is supported, push the associated operation
      acc.push({
        __type: type,
        __path: pathItemObject.__path,
        ...pathItemObject[type],
      })
      return acc
    }, [])
    return acc.concat(pathOperations)
  }, [])

  return operationObjects
}

export default getPathsFromSchema
