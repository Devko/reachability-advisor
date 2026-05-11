const _ = require('lodash');

exports.handler = async function handler(event) {
  const input = JSON.parse(event.body || '{}');
  const order = _.merge({}, input);
  return { statusCode: 200, body: JSON.stringify(order) };
};
