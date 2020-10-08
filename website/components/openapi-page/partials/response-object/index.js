import PropertyObject from '../property-object'

function ResponseObject({ data }) {
  // `schema` can be empty, which means the response does not return content
  //  We currently only support object responses (ie those that have schema.properties) in the UI
  // Ref: https://swagger.io/specification/v2/#response-object
  if (!data || !data.schema || !data.schema.properties) {
    return <div>No content.</div>
  }
  return (
    <div>
      {Object.keys(data.schema.properties).map((propertyKey, idx) => {
        return (
          <PropertyObject
            key={propertyKey}
            name={propertyKey}
            data={data.schema.properties[propertyKey]}
            isFirstItem={idx === 0}
            isLastItem={idx === Object.keys(data.schema.properties).length - 1}
          />
        )
      })}
    </div>
  )
}

export default ResponseObject
