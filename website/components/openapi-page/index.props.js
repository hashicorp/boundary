import PropTypes from 'prop-types'
import OpenAPIPage from '.'

function OpenAPIPageProps(props) {
  return <OpenAPIPage {...props} />
}

OpenAPIPageProps.propTypes = {
  /** Information about the API, pulled from the schema's [Info Object](https://swagger.io/specification/v2/#info-object) */
  info: PropTypes.shape({
    title: PropTypes.string.isRequired,
    description: PropTypes.string,
    version: PropTypes.string,
  }),
  /** The name of the associated HashiCopr product, used in page metadata */
  productName: PropTypes.string,
  /** The slug of the associated HashiCorp product, used for theming. Only supports "boundary" or a default theme at present.*/
  productSlug: PropTypes.oneOf(['boundary']),
  /** An object that determines which operations will be shown on the page */
  operationCategory: PropTypes.shape({
    /** The name of the operation "category", used as the page title */
    name: PropTypes.string,
    /** The slug-ified name, used as the page's location */
    slug: PropTypes.string,
    /** An array of [Operation Objects](https://swagger.io/specification/v2/#operation-object) to be displayed on the page */
    operations: PropTypes.arrayOf(PropTypes.object),
  }),
  /** ["order"](https://github.com/hashicorp/react-components/blob/11d7bda7d518bc675ab0033067d43057e21f3b77/packages/docs-sidenav/index.js#L9) data generated to be passed directly to our DocsSidenav component  */
  sidenavOrderData: PropTypes.object,
}

export default OpenAPIPageProps
