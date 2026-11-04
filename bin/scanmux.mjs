#!/usr/bin/env node
import './typescript-bootstrap.mjs';
const { main } = await import('../src/cli.ts');
process.exitCode = await main(process.argv.slice(2));
