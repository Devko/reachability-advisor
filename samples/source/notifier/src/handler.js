const _ = require('lodash');

exports.handler = async function(event) {
  const body = JSON.parse(event.body || '{}');
  const message = _.merge({status: 'new'}, body);
  return { statusCode: 200, body: JSON.stringify(message) };
};
