import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    fileParallelism: true,
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: false,
        isolate: true,
      },
    },
    // Setup file to suppress PromiseRejectionHandledWarning warnings
    // that occur when testing retry logic with fake timers
    setupFiles: ['./tests/setup.ts'],
    // Ignore unhandled errors that occur with fake timers and async retry logic
    // The retry-executor tests intentionally create rejected promises that are
    // handled asynchronously by the retry mechanism, which triggers Node.js warnings
    dangerouslyIgnoreUnhandledErrors: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.test.ts',
        '**/*.spec.ts',
        'examples/',
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
