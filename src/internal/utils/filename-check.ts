/** File name check for files added to a capsa. */

import { isControl } from './safe-filename.js';

/**
 * Describe why a file name cannot be sent, or return undefined if it can.
 *
 * A sent name must be a plain file name: no "/" or "\", no control characters,
 * not empty or only spaces, and not "." or "..". The message does not repeat
 * the name.
 * @param name - The file name a sender supplied
 */
export function filenameSendProblem(name: string): string | undefined {
  if (name.includes('/') || name.includes('\\')) {
    return 'File name must not contain a path separator ("/" or "\\"). Pass the file name only.';
  }
  for (const ch of name) {
    if (isControl(ch.codePointAt(0) ?? 0)) {
      return 'File name must not contain control characters.';
    }
  }
  if (name.replace(/ /g, '').length === 0) {
    return 'File name must not be empty or only spaces.';
  }
  if (name === '.' || name === '..') {
    return 'File name must not be "." or "..".';
  }
  return undefined;
}
