const _ = require('lodash');

function buildJobConfig(config) {
  return _.merge({ retries: 3, priority: 'normal' }, config);
}

module.exports = { buildJobConfig };
