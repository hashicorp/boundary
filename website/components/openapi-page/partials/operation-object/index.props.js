import React from 'react'
import PropTypes from 'prop-types'
import OperationObject from '.'

function OperationObjectProps(props) {
  return <OperationObject {...props} />
}

/** Displays [Operation Object](https://swagger.io/specification/v2/#operation-object) data to the user. */
OperationObjectProps.propTypes = {
  /** The path to the endpoint where this operation is executed */
  path: PropTypes.string.isRequired,
  /** The type of operation */
  type: PropTypes.oneOf([
    'get',
    'put',
    'post',
    'delete',
    'options',
    'head',
    'patch',
  ]).isRequired,
  /** A subset of [Operation Object](https://swagger.io/specification/v2/#operation-object) relevant to the UI */
  data: PropTypes.shape({
    /** Flag whether this operation is deprecated */
    deprecated: PropTypes.bool,
    /** A unique string used to identify the operation.*/
    operationId: PropTypes.string,
    /** Array of parameter objects. We group them by their "in" property, and pass them to the <PropertyObject /> component for rendering. */
    parameters: PropTypes.arrayOf(
      PropTypes.shape({
        /** The name of the parameter. Parameter names are case sensitive. */
        name: PropTypes.string.isRequired,
        /** A brief, plain text description of the parameter. Note that [GitHub-flavor markdown](https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown) is not currently supported. */
        description: PropTypes.string,
        /** Indicates whether this parameter is mandatory. */
        required: PropTypes.boolean,
        /** The location of the parameter. Note: `formData` and `header` are not currently supported in the UI. */
        in: PropTypes.oneOf(['query', 'path', 'body']).isRequired,
        /** Schema is used for "body" parameters. */
        schema: PropTypes.object,
        /** Type defines the parameter type, for non-"body" parameters. */
        type: PropTypes.oneOf([
          'array',
          'boolean',
          'integer',
          'number',
          'object',
          'string',
        ]),
      })
    ),
    /** Responses object, keys are HTTP response codes */
    responses: PropTypes.shape({
      /** We only support "200" response codes, for now. This object is passed to the <ResponseObject /> component. */
      200: PropTypes.object,
    }),
  }),
}

export default OperationObjectProps
