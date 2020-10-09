const fs = require('fs')
const RefParser = require('@apidevtools/json-schema-ref-parser')

export default async function parseSchema(filePath) {
  const content = JSON.parse(fs.readFileSync(filePath))
  const schema = await RefParser.dereference(content)
  return schema
}
