import { productName, productSlug } from 'data/metadata'
import OpenApiPage from '@hashicorp/react-open-api-page'
/* Used server-side only */
import path from 'path'
import {
  getPathsFromSchema,
  getPropsForPage,
} from '@hashicorp/react-open-api-page/server'
import { processSchemaFile } from '@hashicorp/react-open-api-page/process-schema'

const targetFile = '../internal/gen/controller.swagger.json'
const pathFromRoot = 'api-docs'

export default function OpenApiDocsPage(props) {
  return (
    <OpenApiPage
      {...props}
      productName={productName}
      productSlug={productSlug}
      baseRoute={pathFromRoot}
    />
  )
}

export async function getStaticPaths() {
  const swaggerFile = path.join(process.cwd(), targetFile)
  const schema = await processSchemaFile(swaggerFile)
  const paths = getPathsFromSchema(schema)
  return { paths, fallback: false }
}

export async function getStaticProps({ params }) {
  const swaggerFile = path.join(process.cwd(), targetFile)
  const schema = await processSchemaFile(swaggerFile)
  const props = getPropsForPage(schema, params)
  return { props }
}
