/**
 * SDK version information
 * @file capsara.sdk/typescript/src/internal/version.ts
 *
 * Note: This version should be updated when package.json version changes.
 * Consider using a build step to sync these values automatically.
 */

/** SDK version - must match package.json */
export const SDK_VERSION = '1.0.4';

/** SDK name for User-Agent header */
export const SDK_NAME = 'Capsara-SDK-typescript';

/** Default User-Agent string */
export const DEFAULT_USER_AGENT = `${SDK_NAME}/${SDK_VERSION} (Node.js ${process.version})`;

/**
 * Build User-Agent string with optional custom suffix
 * @param customAgent - Optional custom agent string to append
 * @returns Complete User-Agent string
 */
export function buildUserAgent(customAgent?: string): string {
  if (customAgent) {
    return `${DEFAULT_USER_AGENT} ${customAgent}`;
  }
  return DEFAULT_USER_AGENT;
}
