#!/usr/bin/env node
/**
 * BrightPath Academy — Production Start Script
 * Usage: node start.js [--port=3000] [--env=production]
 */
'use strict';

// Parse CLI args
const args = Object.fromEntries(process.argv.slice(2).map(a => {
  const [k, v] = a.replace('--','').split('=');
  return [k, v || true];
}));

// Set env
process.env.PORT     = args.port || process.env.PORT || 3000;
process.env.NODE_ENV = args.env  || process.env.NODE_ENV || 'development';

// Load .env file if exists
const fs = require('node:fs');
const envFile = args.env === 'production' ? '.env' : '.env';
if (fs.existsSync(envFile)) {
  fs.readFileSync(envFile,'utf8').split('\n').forEach(line => {
    const [k,...v] = line.split('=');
    if (k && !k.startsWith('#') && !process.env[k.trim()]) {
      process.env[k.trim()] = v.join('=').trim().replace(/^['"]|['"]$/g,'');
    }
  });
  console.log(`⚙️  Loaded environment from ${envFile}`);
}

// Verify Node version
const [major] = process.version.slice(1).split('.').map(Number);
if (major < 22) {
  console.error(`❌ Node.js 22+ required (you have ${process.version}). Please upgrade.`);
  process.exit(1);
}

// Start server
console.log(`\n🚀 Starting BrightPath Academy (${process.env.NODE_ENV})...`);
require('./server/index.js');
