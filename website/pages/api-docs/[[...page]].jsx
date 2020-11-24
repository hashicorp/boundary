import { productName, productSlug } from 'data/metadata'
import path from 'path'
import parseSwagger from '../../lib/swagger-parser'
import OpenApiPage, {
  getPathsFromSchema,
  getPropsForPage,
} from '../../components/openapi-page'

const targetFile = '../internal/gen/controller.swagger.json'
const pathFromRoot = 'api-docs'

export default function OpenApiDocsPage(props) {
  return (
    <OpenApiPage
      {...props}
      productName={productName}
      productSlug={productSlug}
      pathFromRoot={pathFromRoot}
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
