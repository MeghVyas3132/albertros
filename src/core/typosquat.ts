// Most-installed npm packages: the names attackers imitate.
export const POPULAR = `react react-dom lodash express axios chalk debug commander moment request vue
typescript webpack babel-core @babel/core eslint prettier jest mocha chai sinon underscore jquery async
bluebird uuid yargs minimist glob rimraf mkdirp fs-extra dotenv cross-env cross-spawn semver colors
body-parser cookie-parser cors helmet morgan nodemon pm2 socket.io ws redis mongoose mongodb mysql mysql2
pg sequelize knex prisma @prisma/client graphql apollo-server next nuxt angular @angular/core rxjs zone.js
classnames prop-types styled-components @emotion/react tailwindcss postcss autoprefixer sass less
node-sass esbuild vite rollup parcel gulp grunt browserify ts-node tsx tslib core-js regenerator-runtime
@types/node @types/react date-fns dayjs luxon moment-timezone immer redux react-redux @reduxjs/toolkit
mobx zustand jotai swr @tanstack/react-query react-router react-router-dom formik yup zod joi ajv
validator qs querystring node-fetch got superagent cheerio puppeteer playwright selenium-webdriver
jsonwebtoken bcrypt bcryptjs passport crypto-js nanoid shortid ethers web3 bignumber.js bn.js
@solana/web3.js electron electron-builder discord.js telegraf openai twilio stripe aws-sdk
@aws-sdk/client-s3 firebase firebase-admin googleapis multer sharp jimp canvas pdfkit nodemailer
winston pino bunyan log4js ora inquirer prompts boxen figlet kleur picocolors ansi-styles supports-color
strip-ansi string-width wrap-ansi cli-table3 chokidar ejs handlebars pug mustache marked markdown-it
highlight.js prismjs d3 chart.js three lottie-web framer-motion gsap animejs socket.io-client
event-stream through2 readable-stream concat-stream once inherits safe-buffer buffer events util
path-to-regexp ms depd http-errors statuses mime mime-types iconv-lite raw-body content-type
ua-parser-js node-ipc coa rc faker @faker-js/faker eslint-scope eslint-config-prettier
babel-loader css-loader style-loader file-loader html-webpack-plugin webpack-cli webpack-dev-server
ts-loader nx lerna turbo husky lint-staged concurrently npm-run-all serve http-server
lodash.merge lodash.get deepmerge object-assign extend xtend is-promise is-number kind-of
color-name color-convert has-flag escape-string-regexp js-yaml yaml xml2js fast-xml-parser
form-data tough-cookie ip ipaddr.js nan node-gyp node-pre-gyp prebuild-install bindings
sqlite3 better-sqlite3 typeorm @nestjs/core @nestjs/common koa fastify hapi restify
`.split(/\s+/).filter(Boolean);

const POPULAR_SET = new Set(POPULAR);

function damerau(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

const norm = (s: string) => s.replace(/^@[^/]+\//, '').replace(/[-_.]/g, '').replace(/js$/, '');

const POPULAR_SCOPES = ['babel', 'types', 'angular', 'aws-sdk', 'nestjs', 'tanstack', 'reduxjs', 'prisma', 'solana', 'emotion', 'faker-js', 'vue', 'sveltejs', 'testing-library', 'typescript-eslint', 'mui', 'nextui-org', 'radix-ui', 'vitest', 'storybook', 'firebase', 'google-cloud', 'azure', 'octokit', 'apollo', 'trpc', 'supabase', 'vercel', 'ethersproject', 'openzeppelin', 'chakra-ui', 'headlessui', 'sentry', 'opentelemetry'];

/** Returns the popular package (or scope) this name imitates, if any. */
export function typosquatOf(name: string): string | null {
  if (POPULAR_SET.has(name)) return null;
  if (name.startsWith('@')) {
    // Only the scope owner can publish inside a scope, so look-alike names *inside* a scope are fine.
    // What is dangerous is a scope that is itself a misspelling of a well-known one.
    const scope = name.slice(1, name.indexOf('/'));
    if (POPULAR_SCOPES.includes(scope) || scope.length < 4) return null;
    for (const ps of POPULAR_SCOPES) {
      if (Math.abs(ps.length - scope.length) <= 1 && damerau(scope, ps, 1) <= 1) return `@${ps}${name.slice(name.indexOf('/'))}`;
    }
    return null;
  }
  for (const p of POPULAR) {
    if (p.startsWith('@')) continue;
    if (p.length < 5) continue;
    if (norm(name) === norm(p) && name.length >= 5) return p;
    const max = p.length >= 9 ? 2 : 1;
    if (Math.abs(name.length - p.length) <= max && damerau(name, p, max) <= max) return p;
  }
  return null;
}
