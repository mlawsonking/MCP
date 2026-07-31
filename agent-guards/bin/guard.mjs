#!/usr/bin/env node
// Entry point for the `guard` command. The implementation is in ../cli so the plugin can bundle the
// same code and run it without an install.

import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { main } = require('../cli/index.js');

process.exitCode = await main(process.argv.slice(2));
