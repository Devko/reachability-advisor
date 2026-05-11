const _ = require('lodash');

exports.handler = async function handler(req) {
  const merged = _.merge({}, req.body || {});
  return { ok: true, merged };
};
