/**
 * Vitest setup file
 *
 * This file configures the test environment before tests run.
 * It suppresses PromiseRejectionHandledWarning warnings that occur when testing
 * retry logic with fake timers - these are expected and not indicative of real issues.
 */

// Suppress PromiseRejectionHandledWarning warnings
// These occur when using fake timers with retry logic that eventually handles rejections
process.on('warning', (warning) => {
  if (warning.name === 'PromiseRejectionHandledWarning') {
    return; // Suppress this warning
  }
  console.warn(warning);
});

// Also handle unhandled rejections that are later handled
process.on('unhandledRejection', () => {
  // Don't crash on unhandled rejections in tests
  // The retry executor tests intentionally create promises that reject
  // and are caught asynchronously by the retry mechanism
});
