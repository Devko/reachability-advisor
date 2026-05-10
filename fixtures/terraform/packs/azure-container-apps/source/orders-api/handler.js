const _ = require('lodash');

exports.handler = async function handler(req) {
  const body = req.body || {};
  const merged = _.merge({}, body);
  return { statusCode: 200, body: JSON.stringify(merged) };
};
