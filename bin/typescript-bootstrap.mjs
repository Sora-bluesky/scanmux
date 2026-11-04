import { readFileSync, realpathSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { pathToFileURL } from 'node:url';

const sourceRoot = new URL('../src/', import.meta.url).href;
const stripWarning = 'stripTypeScriptTypes is an experimental feature and might change at any time';
registerHooks({
  load(url, context, nextLoad) {
    if (!url.startsWith(sourceRoot) || !url.endsWith('.ts') || new URL(url).href !== url
      || decodeURIComponent(url.slice(sourceRoot.length)).split(/[\\/]/).some(part => ['..', 'node_modules'].includes(part))) return nextLoad(url, context);
    const filename = realpathSync(new URL(url));
    if (!pathToFileURL(filename).href.startsWith(sourceRoot)) return nextLoad(url, context);
    const source = readFileSync(filename, 'utf8'), emitWarning = process.emitWarning;
    // Node emits this API notice synchronously; do not silence other warnings or later work.
    process.emitWarning = function (warning, type, ...args) {
      if (warning === stripWarning && type === 'ExperimentalWarning' && args.every(value => value === undefined)) return;
      return Reflect.apply(emitWarning, this, [warning, type, ...args]);
    };
    try { return { format: 'module', source: stripTypeScriptTypes(source, { mode: 'strip', sourceUrl: url }), shortCircuit: true }; }
    finally { process.emitWarning = emitWarning; }
  },
});
