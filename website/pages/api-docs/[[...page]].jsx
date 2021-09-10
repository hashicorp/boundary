import { productName, productSlug } from 'data/metadata'
import OpenApiPage, {
  getPathsFromSchema,
  getPropsForPage,
} from '@hashicorp/react-open-api-page'
/* Used server-side only */
import fs from 'fs'
import path from 'path'
import parseSwagger from '@hashicorp/react-open-api-page/parse-swagger'

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
  const swaggerFile = path.join(process.cwd(), targetFile)
  const schema = await parseSwagger(fs.readFileSync(swaggerFile))
  const paths = getPathsFromSchema(schema)
  return { paths, fallback: false }
}

export async function getStaticProps({ params }) {
  const swaggerFile = path.join(process.cwd(), targetFile)
  const schema = await parseSwagger(fs.readFileSync(swaggerFile))
  const props = getPropsForPage(schema, params)
  return { props }
}
