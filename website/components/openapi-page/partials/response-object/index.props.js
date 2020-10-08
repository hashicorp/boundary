import PropTypes from 'prop-types'
import ResponseObject from '.'

function ResponseObjectProps(props) {
  return <ResponseObject {...props} />
}

ResponseObjectProps.propTypes = {
  /** [Response Object](https://swagger.io/specification/v2/#response-object) data. */
  data: PropTypes.shape({
    /** A [Schema Object](https://swagger.io/specification/v2/#schema-object) that describes the response. Note that we currently only support objects (with schema.properties) responses in the UI. */
    schema: PropTypes.object,
  }),
}

export default ResponseObjectProps
