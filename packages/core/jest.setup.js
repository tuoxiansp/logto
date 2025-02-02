/**
 * Setup environment variables for unit test
 */

import { createMockUtils } from '@logto/shared/esm';
import { createMockQueryResult, createMockPool } from 'slonik';

const { jest } = import.meta;
const { mockEsm, mockEsmWithActual, mockEsmDefault } = createMockUtils(jest);

process.env.DB_URL = 'postgres://mock.db.url';
process.env.ENDPOINT = 'https://logto.test';
process.env.NODE_ENV = 'test';

mockEsm('#src/libraries/logto-config.js', () => ({
  createLogtoConfigLibrary: () => ({ getOidcConfigs: () => ({}) }),
}));

mockEsm('#src/env-set/check-alteration-state.js', () => ({
  checkAlterationState: () => true,
}));

// eslint-disable-next-line unicorn/consistent-function-scoping
mockEsmDefault('#src/env-set/oidc.js', () => () => ({
  issuer: 'https://logto.test/oidc',
}));

await mockEsmWithActual('#src/env-set/index.js', () => ({
  MountedApps: {
    Api: 'api',
    Oidc: 'oidc',
    Console: 'console',
    DemoApp: 'demo-app',
    Welcome: 'welcome',
  },
  // TODO: Remove after clean up of default env sets
  default: {
    get oidc() {
      return {
        issuer: 'https://logto.test/oidc',
      };
    },
    get pool() {
      return createMockPool({ query: async () => createMockQueryResult([]) });
    },
    load: jest.fn(),
  },
}));

// Logger is not considered in all test cases
// eslint-disable-next-line unicorn/consistent-function-scoping
mockEsm('koa-logger', () => ({ default: () => (_, next) => next() }));
