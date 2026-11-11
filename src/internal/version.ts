/** SDK version information, read from the package manifest. */

import { createRequire } from 'module';

const packageManifest = createRequire(import.meta.url)('../../package.json') as { version: string };

export const SDK_VERSION: string = packageManifest.version;

export const SDK_NAME = 'Capsara-SDK-typescript';

export const DEFAULT_USER_AGENT = `${SDK_NAME}/${SDK_VERSION} (Node.js ${process.version})`;

export function buildUserAgent(customAgent?: string): string {
  if (customAgent) {
    return `${DEFAULT_USER_AGENT} ${customAgent}`;
  }
  return DEFAULT_USER_AGENT;
}
