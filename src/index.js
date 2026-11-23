'use strict';

/**
 * security-automation-scripts — public entry point (package.json "main").
 *
 * Re-exports the library API so the package can be used programmatically:
 *
 *   const { analyze, inspect, normalize } = require('security-automation-scripts');
 *
 * The CLI lives in ./cli.js (bin "sec-auto"); it is not loaded here because
 * it runs on execution.
 */

module.exports = {
  ...require('./headers'),
  ...require('./tls'),
  ...require('./log-normalizer'),
};
