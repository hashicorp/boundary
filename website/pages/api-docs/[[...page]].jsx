// import { productName, productSlug } from 'data/metadata'
import path from 'path'
import parseSwagger from '../../lib/swagger-parser'
import OpenApiPage, {
  getPathsFromSchema,
  getPropsForPage,
} from '../../components/openapi-page'

const targetFile = './pages/api-docs/packer-test.swagger.json'
const pathFromRoot = 'api-docs'

export default function OpenApiDocsPage(props) {
  return (
    <OpenApiPage
      {...props}
      productName={'Packer'}
      productSlug={'packer'}
      pathFromRoot={pathFromRoot}
      massageOperationPathFn={(path) =>
        path.replace(
          '/packer/2021-04-30/organizations/{location.organization_id}/projects/{location.project_id}',
          ''
        )
      }
    />
  )
}

export async function getStaticPaths() {
  const schema = await parseSwagger(path.join(process.cwd(), targetFile))
  const paths = getPathsFromSchema(schema)
  return { paths, fallback: false }
}

export async function getStaticProps({ params }) {
  const schema = await parseSwagger(path.join(process.cwd(), targetFile))
  const props = getPropsForPage(schema, params)
  return { props }
}
