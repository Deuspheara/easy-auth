// Fixed inputs only: never scan the workspace or private review documents.
import {build} from 'esbuild';
import {fileURLToPath} from 'node:url';
import {readFile, writeFile, mkdir, copyFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const root = new URL('../../', import.meta.url);
const vendor = new URL('crates/auth-axum/src/pages/vendor/', root);
await mkdir(vendor, {recursive: true});
await copyFile(new URL('node_modules/basecoat-css/dist/basecoat.cdn.min.css', import.meta.url), new URL('basecoat.css', vendor));
await build({stdin: {contents: 'export {animate} from "motion/mini";', resolveDir: fileURLToPath(new URL('.', import.meta.url))}, bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, legalComments: 'eof', outfile: fileURLToPath(new URL('motion.js', vendor))});
for (const name of ['basecoat-css', 'motion', 'framer-motion', 'motion-dom', 'motion-utils', 'tslib', 'esbuild']) {
  const folder = new URL(`node_modules/${name}/`, import.meta.url);
  const pkg = JSON.parse(await readFile(new URL('package.json', folder)));
  const license = name === 'tslib' ? 'LICENSE.txt' : 'LICENSE.md';
  const notice = (await readFile(new URL(license, folder), 'utf8')).replace(/\r\n/g, '\n');
  await writeFile(new URL(`${name}.LICENSE`, vendor), notice);
  console.log(`${name} ${pkg.version}: ${pkg.license}`);
}
await writeFile(new URL('basecoat-popover.js', vendor), (await readFile(new URL('node_modules/basecoat-css/dist/js/basecoat.min.js', import.meta.url), 'utf8')) + '\n' + (await readFile(new URL('node_modules/basecoat-css/dist/js/popover.min.js', import.meta.url), 'utf8')));
const outputs = {};
for (const name of ['basecoat.css', 'motion.js', 'basecoat-popover.js']) {
  const bytes = await readFile(new URL(name, vendor));
  outputs[name] = {bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex')};
}
await writeFile(new URL('assets.json', vendor), JSON.stringify(outputs, null, 2) + '\n');
