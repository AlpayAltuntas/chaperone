import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

interface PackageJson {
  version: string;
}

const pkg = require('../package.json') as PackageJson;

export const VERSION: string = pkg.version;
