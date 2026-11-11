import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    fileParallelism: true,
    pool: 'forks',
    isolate: true,
    globalSetup: ['./tests/fixtures/rsa-keys.setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.test.ts',
        '**/*.spec.ts',
        'examples/',
        'tests/',
      ],
      thresholds: {
        statements: 90,
        branches: 90,
        functions: 90,
        lines: 90,
      },
    },
  },
});
