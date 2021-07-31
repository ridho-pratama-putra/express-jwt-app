// status
////code
////descctiption
//result as array of object

const responseFactory = (status, result) => {
  return {
    status,
    result
  }
}

module.exports = responseFactory
